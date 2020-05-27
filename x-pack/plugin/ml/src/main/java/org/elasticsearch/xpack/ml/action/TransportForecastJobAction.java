/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ml.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.common.notifications.AbstractAuditMessage;
import org.elasticsearch.xpack.core.common.notifications.AbstractAuditor;
import org.elasticsearch.xpack.core.ml.action.ForecastJobAction;
import org.elasticsearch.xpack.core.ml.job.config.AnalysisLimits;
import org.elasticsearch.xpack.core.ml.job.config.Job;
import org.elasticsearch.xpack.core.ml.job.results.ForecastRequestStats;
import org.elasticsearch.xpack.core.ml.utils.ExceptionsHelper;
import org.elasticsearch.xpack.ml.job.JobManager;
import org.elasticsearch.xpack.ml.job.persistence.JobResultsProvider;
import org.elasticsearch.xpack.ml.job.process.autodetect.AutodetectProcessManager;
import org.elasticsearch.xpack.ml.job.process.autodetect.params.ForecastParams;
import org.elasticsearch.xpack.ml.notifications.AnomalyDetectionAuditor;
import org.elasticsearch.xpack.ml.process.NativeStorageProvider;

import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

import static org.elasticsearch.xpack.core.ml.action.ForecastJobAction.Request.DURATION;

public class TransportForecastJobAction extends TransportJobTaskAction<ForecastJobAction.Request,
        ForecastJobAction.Response> {

    private static final Logger logger = LogManager.getLogger(TransportForecastJobAction.class);
    private static final ByteSizeValue FORECAST_LOCAL_STORAGE_LIMIT = new ByteSizeValue(500, ByteSizeUnit.MB);
    private static final ByteSizeValue DEFAULT_MAX_MODEL_MEMORY = new ByteSizeValue(20, ByteSizeUnit.MB);

    private final JobResultsProvider jobResultsProvider;
    private final JobManager jobManager;
    private final NativeStorageProvider nativeStorageProvider;
    private final AnomalyDetectionAuditor auditor;

    @Inject
    public TransportForecastJobAction(TransportService transportService,
                                      ClusterService clusterService, ActionFilters actionFilters,
                                      JobResultsProvider jobResultsProvider, AutodetectProcessManager processManager,
                                      JobManager jobManager, NativeStorageProvider nativeStorageProvider, AnomalyDetectionAuditor auditor) {
        super(ForecastJobAction.NAME, clusterService, transportService, actionFilters,
            ForecastJobAction.Request::new, ForecastJobAction.Response::new,
                ThreadPool.Names.SAME, processManager);
        this.jobResultsProvider = jobResultsProvider;
        this.jobManager = jobManager;
        this.nativeStorageProvider = nativeStorageProvider;
        this.auditor = auditor;
        // ThreadPool.Names.SAME, because operations is executed by autodetect worker thread
    }

    @Override
    protected void taskOperation(ForecastJobAction.Request request, TransportOpenJobAction.JobTask task,
                                 ActionListener<ForecastJobAction.Response> listener) {
        jobManager.getJob(task.getJobId(), ActionListener.wrap(
                job -> {
                    validate(job, request);

                    ForecastParams.Builder paramsBuilder = ForecastParams.builder();

                    if (request.getDuration() != null) {
                        paramsBuilder.duration(request.getDuration());
                    }

                    if (request.getExpiresIn() != null) {
                        paramsBuilder.expiresIn(request.getExpiresIn());
                    }

                    Long adjustedLimit = getAdjustedMemoryLimit(job, request.getMaxModelMemory(), auditor);
                    if (adjustedLimit != null) {
                        paramsBuilder.maxModelMemory(adjustedLimit);
                    }

                    // tmp storage might be null, we do not log here, because it might not be
                    // required
                    Path tmpStorage = nativeStorageProvider.tryGetLocalTmpStorage(task.getDescription(), FORECAST_LOCAL_STORAGE_LIMIT);
                    if (tmpStorage != null) {
                        paramsBuilder.tmpStorage(tmpStorage.toString());
                    }

                    ForecastParams params = paramsBuilder.build();
                    processManager.forecastJob(task, params, e -> {
                        if (e == null) {
                            getForecastRequestStats(request.getJobId(), params.getForecastId(), listener);
                        } else {
                            listener.onFailure(e);
                        }
                    });
                },
                listener::onFailure
        ));
    }

    private void getForecastRequestStats(String jobId, String forecastId, ActionListener<ForecastJobAction.Response> listener) {
        Consumer<ForecastRequestStats> forecastRequestStatsHandler = forecastRequestStats -> {
            if (forecastRequestStats == null) {
                // paranoia case, it should not happen that we do not retrieve a result
                listener.onFailure(new ElasticsearchException(
                        "Cannot run forecast: internal error, please check the logs"));
            } else if (forecastRequestStats.getStatus() == ForecastRequestStats.ForecastRequestStatus.FAILED) {
                List<String> messages = forecastRequestStats.getMessages();
                if (messages.size() > 0) {
                    String message = messages.get(0);

                    // special case: if forecast failed due to insufficient disk space, log the setting
                    if (message.contains("disk space is insufficient")) {
                        message += " Minimum disk space required: [" + processManager.getMinLocalStorageAvailable() + "]";
                    }

                    listener.onFailure(ExceptionsHelper.badRequestException("Cannot run forecast: "
                            + message));
                } else {
                    // paranoia case, it should not be possible to have an empty message list
                    listener.onFailure(
                            new ElasticsearchException(
                                    "Cannot run forecast: internal error, please check the logs"));
                }
            } else {
                listener.onResponse(new ForecastJobAction.Response(true, forecastId));
            }
        };

        jobResultsProvider.getForecastRequestStats(jobId, forecastId, forecastRequestStatsHandler, listener::onFailure);
    }

    static Long getAdjustedMemoryLimit(Job job, Long requestedLimit, AbstractAuditor<? extends AbstractAuditMessage> auditor) {
        if (requestedLimit == null || requestedLimit == DEFAULT_MAX_MODEL_MEMORY.getBytes()) {
            return null;
        }
        long jobLimitMegaBytes = job.getAnalysisLimits() == null || job.getAnalysisLimits().getModelMemoryLimit() == null ?
            AnalysisLimits.DEFAULT_MODEL_MEMORY_LIMIT_MB :
            job.getAnalysisLimits().getModelMemoryLimit();
        long allowedMax = (long)(new ByteSizeValue(jobLimitMegaBytes, ByteSizeUnit.MB).getBytes() * 0.40);
        long adjustedMax = Math.min(requestedLimit, allowedMax - 1);
        if (adjustedMax != requestedLimit) {
            String msg = "requested forecast limit [" +
                requestedLimit +
                "] exceeded [" + allowedMax +
                "] (40% of the anomaly job memory limit). Reducing to allowed maximum before running forecast.";
            logger.warn("[{}] {}", job.getId(), msg);
            auditor.warning(job.getId(), msg);
        }
        return adjustedMax;
    }

    static void validate(Job job, ForecastJobAction.Request request) {
        if (job.getJobVersion() == null || job.getJobVersion().before(Version.fromString("6.1.0"))) {
            throw ExceptionsHelper.badRequestException(
                    "Cannot run forecast because jobs created prior to version 6.1 are not supported");
        }

        if (request.getDuration() != null) {
            TimeValue duration = request.getDuration();
            TimeValue bucketSpan = job.getAnalysisConfig().getBucketSpan();

            if (duration.compareTo(bucketSpan) < 0) {
                throw ExceptionsHelper.badRequestException(
                        "[" + DURATION.getPreferredName() + "] must be greater or equal to the bucket span: ["
                                + duration.getStringRep() + "/" + bucketSpan.getStringRep() + "]");
            }
        }

        if (request.getMaxModelMemory() != null) {
            if (request.getMaxModelMemory() >= FORECAST_LOCAL_STORAGE_LIMIT.getBytes()) {
                throw ExceptionsHelper.badRequestException(
                    "[{}] must be less than 500MB",
                    ForecastJobAction.Request.MAX_MODEL_MEMORY.getPreferredName());
            }
        }

    }
}
