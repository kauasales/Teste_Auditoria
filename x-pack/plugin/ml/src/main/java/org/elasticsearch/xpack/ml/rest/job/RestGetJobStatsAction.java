/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ml.rest.job;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.common.Strings;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;
import org.elasticsearch.xpack.core.ml.action.GetJobsStatsAction;
import org.elasticsearch.xpack.core.ml.job.config.Job;
import org.elasticsearch.xpack.ml.MachineLearning;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.GET;

public class RestGetJobStatsAction extends BaseRestHandler {

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, MachineLearning.BASE_PATH + "anomaly_detectors/{" + Job.ID.getPreferredName() + "}/_stats"),
            new Route(GET, MachineLearning.BASE_PATH + "anomaly_detectors/_stats")
        );
    }

    @Override
    public String getName() {
        return "ml_get_job_stats_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest restRequest, NodeClient client) throws IOException {
        String jobId = restRequest.param(Job.ID.getPreferredName());
        if (Strings.isNullOrEmpty(jobId)) {
            jobId = Metadata.ALL;
        }
        GetJobsStatsAction.Request request = new GetJobsStatsAction.Request(jobId);
        request.setAllowNoMatch(
            restRequest.paramAsBoolean(
                GetJobsStatsAction.Request.ALLOW_NO_MATCH,
                restRequest.paramAsBoolean(GetJobsStatsAction.Request.ALLOW_NO_JOBS, request.allowNoMatch())));
        return channel -> client.execute(GetJobsStatsAction.INSTANCE, request, new RestToXContentListener<>(channel));
    }
}
