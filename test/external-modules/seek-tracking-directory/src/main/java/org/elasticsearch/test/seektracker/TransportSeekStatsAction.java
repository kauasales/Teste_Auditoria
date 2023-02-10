/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.test.seektracker;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.admin.cluster.node.usage.NodesUsageAction;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.LongAdder;

public class TransportSeekStatsAction extends TransportNodesAction<SeekStatsRequest, SeekStatsResponse, SeekStatsRequest, SeekStats> {

    private final SeekStatsService seekStatsService;

    @Inject
    public TransportSeekStatsAction(
        ThreadPool threadPool,
        ClusterService clusterService,
        TransportService transportService,
        ActionFilters actionFilters,
        SeekStatsService seekStatsService
    ) {
        super(
            SeekStatsAction.NAME,
            threadPool,
            clusterService,
            transportService,
            actionFilters,
            SeekStatsRequest::new,
            SeekStatsRequest::new,
            ThreadPool.Names.MANAGEMENT,
            SeekStats.class
        );
        this.seekStatsService = seekStatsService;
    }

    @Override
    protected SeekStatsResponse newResponse(SeekStatsRequest request, List<SeekStats> seekStats, List<FailedNodeException> failures) {
        return new SeekStatsResponse(clusterService.getClusterName(), seekStats, failures);
    }

    @Override
    protected SeekStatsRequest newNodeRequest(SeekStatsRequest request) {
        return request;
    }

    @Override
    protected SeekStats newNodeResponse(StreamInput in, DiscoveryNode node) throws IOException {
        return new SeekStats(in);
    }

    @Override
    protected SeekStats nodeOperation(SeekStatsRequest request, Task task) {
        Map<String, Long> seeks = new HashMap<>();
        if (request.getIndices().length == 0) {
            for (Map.Entry<String, LongAdder> entry : seekStatsService.seeks.entrySet()) {
                seeks.put(entry.getKey(), entry.getValue().longValue());
            }
        } else {
            for (String index : request.getIndices()) {
                LongAdder longAdder = seekStatsService.seeks.get(index);
                seeks.put(index, longAdder.longValue());
            }
        }
        return new SeekStats(clusterService.localNode(), seeks);
    }
}
