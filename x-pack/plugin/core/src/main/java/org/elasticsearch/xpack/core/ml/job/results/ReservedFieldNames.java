/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.job.results;

import org.elasticsearch.xpack.core.ml.datafeed.ChunkingConfig;
import org.elasticsearch.xpack.core.ml.datafeed.DatafeedConfig;
import org.elasticsearch.xpack.core.ml.job.config.AnalysisConfig;
import org.elasticsearch.xpack.core.ml.job.config.AnalysisLimits;
import org.elasticsearch.xpack.core.ml.job.config.CategorizationAnalyzerConfig;
import org.elasticsearch.xpack.core.ml.job.config.DataDescription;
import org.elasticsearch.xpack.core.ml.job.config.DetectionRule;
import org.elasticsearch.xpack.core.ml.job.config.Detector;
import org.elasticsearch.xpack.core.ml.job.config.Job;
import org.elasticsearch.xpack.core.ml.job.config.ModelPlotConfig;
import org.elasticsearch.xpack.core.ml.job.config.Operator;
import org.elasticsearch.xpack.core.ml.job.config.RuleCondition;
import org.elasticsearch.xpack.core.ml.job.persistence.ElasticsearchMappings;
import org.elasticsearch.xpack.core.ml.job.process.autodetect.state.DataCounts;
import org.elasticsearch.xpack.core.ml.job.process.autodetect.state.ModelSizeStats;
import org.elasticsearch.xpack.core.ml.job.process.autodetect.state.ModelSnapshot;
import org.elasticsearch.xpack.core.ml.job.process.autodetect.state.ModelSnapshotField;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;


/**
 * Defines the field names that we use for our results.
 * Fields from the raw data with these names are not added to any result.  Even
 * different types of results will not have raw data fields with reserved names
 * added to them, as it could create confusion if in some results a given field
 * contains raw data and in others it contains some aspect of our output.
 */
public final class ReservedFieldNames {
    private static final Pattern DOT_PATTERN = Pattern.compile("\\.");

    /**
     * This array should be updated to contain all the field names that appear
     * in any documents we store in our results index.  (The reason it's any
     * documents we store and not just results documents is that Elasticsearch
     * 2.x requires mappings for given fields be consistent across all types
     * in a given index.)
     */
    private static final String[] RESERVED_RESULT_FIELD_NAME_ARRAY = {
            ElasticsearchMappings.ALL_FIELD_VALUES,

            Job.ID.getPreferredName(),

            AnomalyCause.PROBABILITY.getPreferredName(),
            AnomalyCause.OVER_FIELD_NAME.getPreferredName(),
            AnomalyCause.OVER_FIELD_VALUE.getPreferredName(),
            AnomalyCause.BY_FIELD_NAME.getPreferredName(),
            AnomalyCause.BY_FIELD_VALUE.getPreferredName(),
            AnomalyCause.CORRELATED_BY_FIELD_VALUE.getPreferredName(),
            AnomalyCause.PARTITION_FIELD_NAME.getPreferredName(),
            AnomalyCause.PARTITION_FIELD_VALUE.getPreferredName(),
            AnomalyCause.FUNCTION.getPreferredName(),
            AnomalyCause.FUNCTION_DESCRIPTION.getPreferredName(),
            AnomalyCause.TYPICAL.getPreferredName(),
            AnomalyCause.ACTUAL.getPreferredName(),
            AnomalyCause.INFLUENCERS.getPreferredName(),
            AnomalyCause.FIELD_NAME.getPreferredName(),

            AnomalyRecord.PROBABILITY.getPreferredName(),
            AnomalyRecord.BY_FIELD_NAME.getPreferredName(),
            AnomalyRecord.BY_FIELD_VALUE.getPreferredName(),
            AnomalyRecord.CORRELATED_BY_FIELD_VALUE.getPreferredName(),
            AnomalyRecord.PARTITION_FIELD_NAME.getPreferredName(),
            AnomalyRecord.PARTITION_FIELD_VALUE.getPreferredName(),
            AnomalyRecord.FUNCTION.getPreferredName(),
            AnomalyRecord.FUNCTION_DESCRIPTION.getPreferredName(),
            AnomalyRecord.TYPICAL.getPreferredName(),
            AnomalyRecord.ACTUAL.getPreferredName(),
            AnomalyRecord.INFLUENCERS.getPreferredName(),
            AnomalyRecord.FIELD_NAME.getPreferredName(),
            AnomalyRecord.OVER_FIELD_NAME.getPreferredName(),
            AnomalyRecord.OVER_FIELD_VALUE.getPreferredName(),
            AnomalyRecord.CAUSES.getPreferredName(),
            AnomalyRecord.RECORD_SCORE.getPreferredName(),
            AnomalyRecord.INITIAL_RECORD_SCORE.getPreferredName(),
            AnomalyRecord.BUCKET_SPAN.getPreferredName(),

            Bucket.ANOMALY_SCORE.getPreferredName(),
            Bucket.BUCKET_INFLUENCERS.getPreferredName(),
            Bucket.BUCKET_SPAN.getPreferredName(),
            Bucket.EVENT_COUNT.getPreferredName(),
            Bucket.INITIAL_ANOMALY_SCORE.getPreferredName(),
            Bucket.PROCESSING_TIME_MS.getPreferredName(),
            Bucket.PARTITION_SCORES.getPreferredName(),
            Bucket.SCHEDULED_EVENTS.getPreferredName(),

            BucketInfluencer.INITIAL_ANOMALY_SCORE.getPreferredName(), BucketInfluencer.ANOMALY_SCORE.getPreferredName(),
            BucketInfluencer.RAW_ANOMALY_SCORE.getPreferredName(), BucketInfluencer.PROBABILITY.getPreferredName(),

            CategoryDefinition.CATEGORY_ID.getPreferredName(),
            CategoryDefinition.TERMS.getPreferredName(),
            CategoryDefinition.REGEX.getPreferredName(),
            CategoryDefinition.MAX_MATCHING_LENGTH.getPreferredName(),
            CategoryDefinition.EXAMPLES.getPreferredName(),

            DataCounts.PROCESSED_RECORD_COUNT.getPreferredName(),
            DataCounts.PROCESSED_FIELD_COUNT.getPreferredName(),
            DataCounts.INPUT_BYTES.getPreferredName(),
            DataCounts.INPUT_RECORD_COUNT.getPreferredName(),
            DataCounts.INPUT_FIELD_COUNT.getPreferredName(),
            DataCounts.INVALID_DATE_COUNT.getPreferredName(),
            DataCounts.MISSING_FIELD_COUNT.getPreferredName(),
            DataCounts.OUT_OF_ORDER_TIME_COUNT.getPreferredName(),
            DataCounts.EMPTY_BUCKET_COUNT.getPreferredName(),
            DataCounts.SPARSE_BUCKET_COUNT.getPreferredName(),
            DataCounts.BUCKET_COUNT.getPreferredName(),
            DataCounts.LATEST_RECORD_TIME.getPreferredName(),
            DataCounts.EARLIEST_RECORD_TIME.getPreferredName(),
            DataCounts.LAST_DATA_TIME.getPreferredName(),
            DataCounts.LATEST_EMPTY_BUCKET_TIME.getPreferredName(),
            DataCounts.LATEST_SPARSE_BUCKET_TIME.getPreferredName(),

            Detector.DETECTOR_INDEX.getPreferredName(),

            Influence.INFLUENCER_FIELD_NAME.getPreferredName(),
            Influence.INFLUENCER_FIELD_VALUES.getPreferredName(),

            Influencer.PROBABILITY.getPreferredName(),
            Influencer.INFLUENCER_FIELD_NAME.getPreferredName(),
            Influencer.INFLUENCER_FIELD_VALUE.getPreferredName(),
            Influencer.INITIAL_INFLUENCER_SCORE.getPreferredName(),
            Influencer.INFLUENCER_SCORE.getPreferredName(),
            Influencer.BUCKET_SPAN.getPreferredName(),

            ModelPlot.PARTITION_FIELD_NAME.getPreferredName(), ModelPlot.PARTITION_FIELD_VALUE.getPreferredName(),
            ModelPlot.OVER_FIELD_NAME.getPreferredName(), ModelPlot.OVER_FIELD_VALUE.getPreferredName(),
            ModelPlot.BY_FIELD_NAME.getPreferredName(), ModelPlot.BY_FIELD_VALUE.getPreferredName(),
            ModelPlot.MODEL_FEATURE.getPreferredName(), ModelPlot.MODEL_LOWER.getPreferredName(),
            ModelPlot.MODEL_UPPER.getPreferredName(), ModelPlot.MODEL_MEDIAN.getPreferredName(),
            ModelPlot.ACTUAL.getPreferredName(),

            Forecast.FORECAST_LOWER.getPreferredName(), Forecast.FORECAST_UPPER.getPreferredName(),
            Forecast.FORECAST_PREDICTION.getPreferredName(),
            Forecast.FORECAST_ID.getPreferredName(),

            //re-use: TIMESTAMP
            ForecastRequestStats.START_TIME.getPreferredName(),
            ForecastRequestStats.END_TIME.getPreferredName(),
            ForecastRequestStats.CREATE_TIME.getPreferredName(),
            ForecastRequestStats.EXPIRY_TIME.getPreferredName(),
            ForecastRequestStats.MESSAGES.getPreferredName(),
            ForecastRequestStats.PROGRESS.getPreferredName(),
            ForecastRequestStats.STATUS.getPreferredName(),
            ForecastRequestStats.MEMORY_USAGE.getPreferredName(),

            ModelSizeStats.MODEL_BYTES_FIELD.getPreferredName(),
            ModelSizeStats.TOTAL_BY_FIELD_COUNT_FIELD.getPreferredName(),
            ModelSizeStats.TOTAL_OVER_FIELD_COUNT_FIELD.getPreferredName(),
            ModelSizeStats.TOTAL_PARTITION_FIELD_COUNT_FIELD.getPreferredName(),
            ModelSizeStats.BUCKET_ALLOCATION_FAILURES_COUNT_FIELD.getPreferredName(),
            ModelSizeStats.MEMORY_STATUS_FIELD.getPreferredName(),
            ModelSizeStats.LOG_TIME_FIELD.getPreferredName(),

            ModelSnapshot.DESCRIPTION.getPreferredName(),
            ModelSnapshotField.SNAPSHOT_ID.getPreferredName(),
            ModelSnapshot.SNAPSHOT_DOC_COUNT.getPreferredName(),
            ModelSnapshot.LATEST_RECORD_TIME.getPreferredName(),
            ModelSnapshot.LATEST_RESULT_TIME.getPreferredName(),
            ModelSnapshot.RETAIN.getPreferredName(),

            Result.RESULT_TYPE.getPreferredName(),
            Result.TIMESTAMP.getPreferredName(),
            Result.IS_INTERIM.getPreferredName()
    };

    /**
     * This array should be updated to contain all the field names that appear
     * in any documents we store in our config index.
     */
    private static final String[] RESERVED_CONFIG_FIELD_NAME_ARRAY = {
            Job.ID.getPreferredName(),
            Job.JOB_TYPE.getPreferredName(),
            Job.JOB_VERSION.getPreferredName(),
            Job.GROUPS.getPreferredName(),
            Job.ANALYSIS_CONFIG.getPreferredName(),
            Job.ANALYSIS_LIMITS.getPreferredName(),
            Job.CREATE_TIME.getPreferredName(),
            Job.CUSTOM_SETTINGS.getPreferredName(),
            Job.DATA_DESCRIPTION.getPreferredName(),
            Job.DESCRIPTION.getPreferredName(),
            Job.FINISHED_TIME.getPreferredName(),
            Job.LAST_DATA_TIME.getPreferredName(),
            Job.ESTABLISHED_MODEL_MEMORY.getPreferredName(),
            Job.MODEL_PLOT_CONFIG.getPreferredName(),
            Job.RENORMALIZATION_WINDOW_DAYS.getPreferredName(),
            Job.BACKGROUND_PERSIST_INTERVAL.getPreferredName(),
            Job.MODEL_SNAPSHOT_RETENTION_DAYS.getPreferredName(),
            Job.RESULTS_RETENTION_DAYS.getPreferredName(),
            Job.MODEL_SNAPSHOT_ID.getPreferredName(),
            Job.RESULTS_INDEX_NAME.getPreferredName(),
            Job.DELETED.getPreferredName(),

            AnalysisConfig.BUCKET_SPAN.getPreferredName(),
            AnalysisConfig.CATEGORIZATION_FIELD_NAME.getPreferredName(),
            AnalysisConfig.CATEGORIZATION_FILTERS.getPreferredName(),
            AnalysisConfig.CATEGORIZATION_ANALYZER.getPreferredName(),
            AnalysisConfig.LATENCY.getPreferredName(),
            AnalysisConfig.SUMMARY_COUNT_FIELD_NAME.getPreferredName(),
            AnalysisConfig.DETECTORS.getPreferredName(),
            AnalysisConfig.INFLUENCERS.getPreferredName(),
            AnalysisConfig.OVERLAPPING_BUCKETS.getPreferredName(),
            AnalysisConfig.RESULT_FINALIZATION_WINDOW.getPreferredName(),
            AnalysisConfig.MULTIVARIATE_BY_FIELDS.getPreferredName(),
            AnalysisConfig.USE_PER_PARTITION_NORMALIZATION.getPreferredName(),

            AnalysisLimits.MODEL_MEMORY_LIMIT.getPreferredName(),
            AnalysisLimits.CATEGORIZATION_EXAMPLES_LIMIT.getPreferredName(),

            CategorizationAnalyzerConfig.CHAR_FILTERS.getPreferredName(),
            CategorizationAnalyzerConfig.TOKENIZER.getPreferredName(),
            CategorizationAnalyzerConfig.TOKEN_FILTERS.getPreferredName(),

            Detector.DETECTOR_DESCRIPTION_FIELD.getPreferredName(),
            Detector.FUNCTION_FIELD.getPreferredName(),
            Detector.FIELD_NAME_FIELD.getPreferredName(),
            Detector.BY_FIELD_NAME_FIELD.getPreferredName(),
            Detector.OVER_FIELD_NAME_FIELD.getPreferredName(),
            Detector.PARTITION_FIELD_NAME_FIELD.getPreferredName(),
            Detector.USE_NULL_FIELD.getPreferredName(),
            Detector.EXCLUDE_FREQUENT_FIELD.getPreferredName(),
            Detector.CUSTOM_RULES_FIELD.getPreferredName(),
            Detector.DETECTOR_INDEX.getPreferredName(),

            DetectionRule.ACTIONS_FIELD.getPreferredName(),
            DetectionRule.CONDITIONS_FIELD.getPreferredName(),
            DetectionRule.SCOPE_FIELD.getPreferredName(),
            RuleCondition.APPLIES_TO_FIELD.getPreferredName(),
            RuleCondition.VALUE_FIELD.getPreferredName(),
            Operator.OPERATOR_FIELD.getPreferredName(),

            DataDescription.FORMAT_FIELD.getPreferredName(),
            DataDescription.TIME_FIELD_NAME_FIELD.getPreferredName(),
            DataDescription.TIME_FORMAT_FIELD.getPreferredName(),
            DataDescription.FIELD_DELIMITER_FIELD.getPreferredName(),
            DataDescription.QUOTE_CHARACTER_FIELD.getPreferredName(),

            ModelPlotConfig.ENABLED_FIELD.getPreferredName(),
            ModelPlotConfig.TERMS_FIELD.getPreferredName(),

            DatafeedConfig.ID.getPreferredName(),
            DatafeedConfig.QUERY_DELAY.getPreferredName(),
            DatafeedConfig.FREQUENCY.getPreferredName(),
            DatafeedConfig.INDICES.getPreferredName(),
            DatafeedConfig.TYPES.getPreferredName(),
            DatafeedConfig.QUERY.getPreferredName(),
            DatafeedConfig.SCROLL_SIZE.getPreferredName(),
            DatafeedConfig.AGGREGATIONS.getPreferredName(),
            DatafeedConfig.SCRIPT_FIELDS.getPreferredName(),
            DatafeedConfig.CHUNKING_CONFIG.getPreferredName(),
            DatafeedConfig.HEADERS.getPreferredName(),

            ChunkingConfig.MODE_FIELD.getPreferredName(),
            ChunkingConfig.TIME_SPAN_FIELD.getPreferredName(),

            ElasticsearchMappings.CONFIG_TYPE
    };

    /**
     * Test if fieldName is one of the reserved result fieldnames or if it contains
     * dots then that the segment before the first dot is not a reserved results
     * fieldname. A fieldName containing dots represents nested fields in which
     * case we only care about the top level.
     *
     * @param fieldName Document field name. This may contain dots '.'
     * @return True if fieldName is not a reserved results fieldname or the top level segment
     * is not a reserved name.
     */
    public static boolean isValidFieldName(String fieldName) {
        String[] segments = DOT_PATTERN.split(fieldName);
        return RESERVED_RESULT_FIELD_NAMES.contains(segments[0]) == false;
    }

    /**
     * A set of all reserved field names in our results.  Fields from the raw
     * data with these names are not added to any result.
     */
    public static final Set<String> RESERVED_RESULT_FIELD_NAMES = new HashSet<>(Arrays.asList(RESERVED_RESULT_FIELD_NAME_ARRAY));

    /**
     * A set of all reserved field names in our config.
     */
    public static final Set<String> RESERVED_CONFIG_FIELD_NAMES = new HashSet<>(Arrays.asList(RESERVED_CONFIG_FIELD_NAME_ARRAY));

    private ReservedFieldNames() {
    }
}
