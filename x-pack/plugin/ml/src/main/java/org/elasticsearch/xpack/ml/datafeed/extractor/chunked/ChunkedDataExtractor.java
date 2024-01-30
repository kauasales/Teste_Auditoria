/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.ml.datafeed.extractor.chunked;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionRequestBuilder;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchRequestBuilder;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.Aggregations;
import org.elasticsearch.search.aggregations.metrics.Max;
import org.elasticsearch.search.aggregations.metrics.Min;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.xpack.core.ClientHelper;
import org.elasticsearch.xpack.core.ml.datafeed.DatafeedConfig;
import org.elasticsearch.xpack.core.ml.datafeed.SearchInterval;
import org.elasticsearch.xpack.core.rollup.action.RollupSearchAction;
import org.elasticsearch.xpack.ml.datafeed.DatafeedTimingStatsReporter;
import org.elasticsearch.xpack.ml.datafeed.extractor.DataExtractor;
import org.elasticsearch.xpack.ml.datafeed.extractor.DataExtractorFactory;
import org.elasticsearch.xpack.ml.datafeed.extractor.DataExtractorUtils;
import org.elasticsearch.xpack.ml.datafeed.extractor.aggregation.RollupDataExtractorFactory;

import java.io.IOException;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;

/**
 * A wrapper {@link DataExtractor} that can be used with other extractors in order to perform
 * searches in smaller chunks of the time range.
 *
 * <p> The chunk span can be either specified or not. When not specified,
 * a heuristic is employed (see {@link #setUpChunkedSearch()}) to automatically determine the chunk span.
 * The search is set up by querying a data summary for the given time range
 * that includes the number of total hits and the earliest/latest times. Those are then used to determine the chunk span,
 * when necessary, and to jump the search forward to the time where the earliest data can be found.
 * If a search for a chunk returns empty, the set up is performed again for the remaining time.
 *
 * <p> Cancellation's behaviour depends on the delegate extractor.
 *
 * <p> Note that this class is NOT thread-safe.
 */
public class ChunkedDataExtractor implements DataExtractor {

    private static final Logger LOGGER = LogManager.getLogger(ChunkedDataExtractor.class);

    private static final String EARLIEST_TIME = "earliest_time";
    private static final String LATEST_TIME = "latest_time";

    /** Let us set a minimum chunk span of 1 minute */
    private static final long MIN_CHUNK_SPAN = 60000L;

    private final Client client;
    private final DataExtractorFactory dataExtractorFactory;
    private final ChunkedDataExtractorContext context;
    private final DataSummaryFactory dataSummaryFactory;
    private final DatafeedTimingStatsReporter timingStatsReporter;
    private long currentStart;
    private long currentEnd;
    private long chunkSpan;
    private boolean isCancelled;
    private DataExtractor currentExtractor;

    public ChunkedDataExtractor(
        Client client,
        DataExtractorFactory dataExtractorFactory,
        ChunkedDataExtractorContext context,
        DatafeedTimingStatsReporter timingStatsReporter
    ) {
        this.client = Objects.requireNonNull(client);
        this.dataExtractorFactory = Objects.requireNonNull(dataExtractorFactory);
        this.context = Objects.requireNonNull(context);
        this.timingStatsReporter = Objects.requireNonNull(timingStatsReporter);
        this.currentStart = context.start;
        this.currentEnd = context.start;
        this.isCancelled = false;
        this.dataSummaryFactory = new DataSummaryFactory();
    }

    @Override
    public DataSummary getSummary() {
        return null;
    }

    @Override
    public boolean hasNext() {
        boolean currentHasNext = currentExtractor != null && currentExtractor.hasNext();
        if (isCancelled()) {
            return currentHasNext;
        }
        return currentHasNext || currentEnd < context.end;
    }

    @Override
    public Result next() throws IOException {
        if (hasNext() == false) {
            throw new NoSuchElementException();
        }

        if (currentExtractor == null) {
            // This is the first time next is called
            setUpChunkedSearch();
        }

        return getNextStream();
    }

    private void setUpChunkedSearch() {
        DataSummary dataSummary = dataSummaryFactory.buildDataSummary();
        if (dataSummary.hasData()) {
            currentStart = context.timeAligner.alignToFloor(dataSummary.earliestTime());
            currentEnd = currentStart;

            if (context.chunkSpan != null) {
                chunkSpan = context.chunkSpan.getMillis();
            } else if (context.hasAggregations) {
                // This heuristic is a direct copy of the manual chunking config auto-creation done in {@link DatafeedConfig}
                chunkSpan = DatafeedConfig.DEFAULT_AGGREGATION_CHUNKING_BUCKETS * context.histogramInterval;
            } else {
                long timeSpread = dataSummary.latestTime() - dataSummary.earliestTime();
                if (timeSpread <= 0) {
                    chunkSpan = context.end - currentEnd;
                } else {
                    // The heuristic here is that we want a time interval where we expect roughly scrollSize documents
                    // (assuming data are uniformly spread over time).
                    // We have totalHits documents over dataTimeSpread (latestTime - earliestTime), we want scrollSize documents over chunk.
                    // Thus, the interval would be (scrollSize * dataTimeSpread) / totalHits.
                    // However, assuming this as the chunk span may often lead to half-filled pages or empty searches.
                    // It is beneficial to take a multiple of that. Based on benchmarking, we set this to 10x.
                    chunkSpan = Math.max(MIN_CHUNK_SPAN, 10 * (context.scrollSize * timeSpread) / dataSummary.totalHits());
                }
            }

            chunkSpan = context.timeAligner.alignToCeil(chunkSpan);
            LOGGER.debug("[{}] Chunked search configured: chunk span = {} ms", context.jobId, chunkSpan);
        } else {
            // search is over
            currentEnd = context.end;
            LOGGER.debug("[{}] Chunked search configured: no data found", context.jobId);
        }
    }

    protected SearchResponse executeSearchRequest(ActionRequestBuilder<SearchRequest, SearchResponse> searchRequestBuilder) {
        SearchResponse searchResponse = ClientHelper.executeWithHeaders(
            context.headers,
            ClientHelper.ML_ORIGIN,
            client,
            searchRequestBuilder::get
        );
        boolean success = false;
        try {
            checkForSkippedClusters(searchResponse);
            success = true;
        } finally {
            if (success == false) {
                searchResponse.decRef();
            }
        }
        return searchResponse;
    }

    private Result getNextStream() throws IOException {
        SearchInterval lastSearchInterval = new SearchInterval(context.start, context.end);
        while (hasNext()) {
            boolean isNewSearch = false;

            if (currentExtractor == null || currentExtractor.hasNext() == false) {
                // First search or the current search finished; we can advance to the next search
                advanceTime();
                isNewSearch = true;
            }

            Result result = currentExtractor.next();
            lastSearchInterval = result.searchInterval();
            if (result.data().isPresent()) {
                return result;
            }

            if (isNewSearch && hasNext()) {
                // If it was a new search it means it returned 0 results. Thus,
                // we reconfigure and jump to the next time interval where there are data.
                // In theory, if everything is consistent, it would be sufficient to call
                // setUpChunkedSearch() here. However, the way that works is to take the
                // query from the datafeed config and add on some simple aggregations.
                // These aggregations are completely separate from any that might be defined
                // in the datafeed config. It is possible that the aggregations in the
                // datafeed config rather than the query are responsible for no data being
                // found. For example, "filter" or "bucket_selector" aggregations can do this.
                // Originally we thought this situation would never happen, with the query
                // selecting data and the aggregations just grouping it, but recently we've
                // seen cases of users filtering in the aggregations. Therefore, we
                // unconditionally advance the start time by one chunk here. setUpChunkedSearch()
                // might then advance substantially further, but in the pathological cases
                // where setUpChunkedSearch() thinks data exists at the current start time
                // while the datafeed's own aggregation doesn't, at least we'll step forward
                // a little bit rather than go into an infinite loop.
                currentStart += chunkSpan;
                setUpChunkedSearch();
            }
        }
        return new Result(lastSearchInterval, Optional.empty());
    }

    private void advanceTime() {
        currentStart = currentEnd;
        currentEnd = Math.min(currentStart + chunkSpan, context.end);
        currentExtractor = dataExtractorFactory.newExtractor(currentStart, currentEnd);
        LOGGER.debug("[{}] advances time to [{}, {})", context.jobId, currentStart, currentEnd);
    }

    @Override
    public boolean isCancelled() {
        return isCancelled;
    }

    @Override
    public void cancel() {
        if (currentExtractor != null) {
            currentExtractor.cancel();
        }
        isCancelled = true;
    }

    @Override
    public void destroy() {
        cancel();
        if (currentExtractor != null) {
            currentExtractor.destroy();
        }
    }

    @Override
    public long getEndTime() {
        return context.end;
    }

    ChunkedDataExtractorContext getContext() {
        return context;
    }

    private class DataSummaryFactory {

        /**
         * If there are aggregations, an AggregatedDataSummary object is created. It returns a ScrollingDataSummary otherwise.
         *
         * By default a DatafeedConfig with aggregations, should already have a manual ChunkingConfig created.
         * However, the end user could have specifically set the ChunkingConfig to AUTO, which would not really work for aggregations.
         * So, if we need to gather an appropriate chunked time for aggregations, we can utilize the AggregatedDataSummary
         *
         * @return DataSummary object
         */
        private DataSummary buildDataSummary() {
            return context.hasAggregations ? newAggregatedDataSummary() : newScrolledDataSummary();
        }

        private DataSummary newScrolledDataSummary() {
            SearchRequestBuilder searchRequestBuilder = rangeSearchRequest();

            SearchResponse searchResponse = executeSearchRequest(searchRequestBuilder);
            try {
                LOGGER.debug("[{}] Scrolling Data summary response was obtained", context.jobId);
                timingStatsReporter.reportSearchDuration(searchResponse.getTook());

                Aggregations aggregations = searchResponse.getAggregations();
                long totalHits = searchResponse.getHits().getTotalHits().value;
                if (totalHits == 0) {
                    return new DataSummary(null, null, 0L);
                } else {
                    long earliestTime = (long) (aggregations.<Min>get(EARLIEST_TIME)).value();
                    long latestTime = (long) (aggregations.<Max>get(LATEST_TIME)).value();
                    return new DataSummary(earliestTime, latestTime, totalHits);
                }
            } finally {
                searchResponse.decRef();
            }
        }

        private DataSummary newAggregatedDataSummary() {
            // TODO: once RollupSearchAction is changed from indices:admin* to indices:data/read/* this branch is not needed
            ActionRequestBuilder<SearchRequest, SearchResponse> searchRequestBuilder =
                dataExtractorFactory instanceof RollupDataExtractorFactory ? rollupRangeSearchRequest() : rangeSearchRequest();
            SearchResponse searchResponse = executeSearchRequest(searchRequestBuilder);
            try {
                LOGGER.debug("[{}] Aggregating Data summary response was obtained", context.jobId);
                timingStatsReporter.reportSearchDuration(searchResponse.getTook());

                Aggregations aggregations = searchResponse.getAggregations();
                // This can happen if all the indices the datafeed is searching are deleted after it started.
                // Note that unlike the scrolled data summary method above we cannot check for this situation
                // by checking for zero hits, because aggregations that work on rollups return zero hits even
                // when they retrieve data.
                if (aggregations == null) {
                    return new DataSummary(null, null, null);
                } else {
                    long earliestTime = (long) (aggregations.<Min>get(EARLIEST_TIME)).value();
                    long latestTime = (long) (aggregations.<Max>get(LATEST_TIME)).value();
                    return new DataSummary(earliestTime, latestTime, null);
                }
            } finally {
                searchResponse.decRef();
            }
        }

        private SearchSourceBuilder rangeSearchBuilder() {
            return new SearchSourceBuilder().size(0)
                .query(DataExtractorUtils.wrapInTimeRangeQuery(context.query, context.timeField, currentStart, context.end))
                .runtimeMappings(context.runtimeMappings)
                .aggregation(AggregationBuilders.min(EARLIEST_TIME).field(context.timeField))
                .aggregation(AggregationBuilders.max(LATEST_TIME).field(context.timeField));
        }

        private SearchRequestBuilder rangeSearchRequest() {
            return new SearchRequestBuilder(client).setIndices(context.indices)
                .setIndicesOptions(context.indicesOptions)
                .setSource(rangeSearchBuilder())
                .setAllowPartialSearchResults(false)
                .setTrackTotalHits(true);
        }

        private RollupSearchAction.RequestBuilder rollupRangeSearchRequest() {
            SearchRequest searchRequest = new SearchRequest().indices(context.indices)
                .indicesOptions(context.indicesOptions)
                .allowPartialSearchResults(false)
                .source(rangeSearchBuilder());
            return new RollupSearchAction.RequestBuilder(client, searchRequest);
        }
    }
}
