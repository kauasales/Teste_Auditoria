/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.action.search;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.node.ResponseCollectorService;
import org.elasticsearch.search.SearchPhaseResult;
import org.elasticsearch.search.query.QuerySearchResult;

import java.util.Objects;

/**
 * A wrapper of search action listeners (search results) that unwraps the query
 * result to get the piggybacked queue size and service time EWMA, adding those
 * values to the coordinating nodes' {@code ResponseCollectorService}.
 */
final class SearchExecutionStatsCollector implements ActionListener<SearchPhaseResult> {

    private final SearchActionListener<SearchPhaseResult> listener;
    private final ResponseCollectorService collector;
    private final long startNanos;

    SearchExecutionStatsCollector(SearchActionListener<SearchPhaseResult> listener,
                                  ResponseCollectorService collector) {
        this.listener = Objects.requireNonNull(listener, "listener cannot be null");
        this.collector = Objects.requireNonNull(collector, "response collector cannot be null");
        this.startNanos = System.nanoTime();
    }

    @Override
    public void onResponse(SearchPhaseResult response) {
        QuerySearchResult queryResult = response.queryResult();
        if (queryResult != null) {
            final long serviceTimeEWMA = queryResult.serviceTimeEWMA();
            final int queueSize = queryResult.nodeQueueSize();
            final long responseDuration = System.nanoTime() - startNanos;
            final String nodeId = listener.searchShardTarget.getNodeId();
            // EWMA/queue size may be -1 if the query node doesn't support capturing it
            if (nodeId != null && serviceTimeEWMA > 0 && queueSize > 0) {
                collector.addNodeStatistics(nodeId, queueSize, responseDuration, serviceTimeEWMA);
            }
        }
        listener.onResponse(response);
    }

    @Override
    public void onFailure(Exception e) {
        listener.onFailure(e);
    }
}
