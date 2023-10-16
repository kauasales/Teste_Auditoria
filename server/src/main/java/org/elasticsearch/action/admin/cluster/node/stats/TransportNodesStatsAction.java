/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.admin.cluster.node.stats;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.node.NodeService;
import org.elasticsearch.tasks.CancellableTask;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.tasks.TaskId;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.transport.Transports;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TransportNodesStatsAction extends TransportNodesAction<
    NodesStatsRequest,
    NodesStatsResponse,
    TransportNodesStatsAction.NodeStatsRequest,
    NodeStats> {

    private final NodeService nodeService;

    @Inject
    public TransportNodesStatsAction(
        ThreadPool threadPool,
        ClusterService clusterService,
        TransportService transportService,
        NodeService nodeService,
        ActionFilters actionFilters
    ) {
        super(
            NodesStatsAction.NAME,
            threadPool,
            clusterService,
            transportService,
            actionFilters,
            NodesStatsRequest::new,
            NodeStatsRequest::new,
            threadPool.executor(ThreadPool.Names.MANAGEMENT)
        );
        this.nodeService = nodeService;
    }

    @Override
    protected NodesStatsResponse newResponse(NodesStatsRequest request, List<NodeStats> responses, List<FailedNodeException> failures) {
        return new NodesStatsResponse(clusterService.getClusterName(), responses, failures);
    }

    @Override
    protected NodeStatsRequest newNodeRequest(NodesStatsRequest request) {
        return new NodeStatsRequest(request);
    }

    @Override
    protected NodeStats newNodeResponse(StreamInput in, DiscoveryNode node) throws IOException {
        assert Transports.assertNotTransportThread("deserializing node stats is too expensive for a transport thread");
        return new NodeStats(in);
    }

    @Override
    protected NodeStats nodeOperation(NodeStatsRequest nodeStatsRequest, Task task) {
        assert task instanceof CancellableTask;

        NodesStatsRequest request = nodeStatsRequest.request;
        Set<String> metrics = request.requestedMetrics();
        return nodeService.stats(
            request.indices(),
            request.includeShardsStats(),
            NodesStatsMetrics.Metric.OS.containedIn(metrics),
            NodesStatsMetrics.Metric.PROCESS.containedIn(metrics),
            NodesStatsMetrics.Metric.JVM.containedIn(metrics),
            NodesStatsMetrics.Metric.THREAD_POOL.containedIn(metrics),
            NodesStatsMetrics.Metric.FS.containedIn(metrics),
            NodesStatsMetrics.Metric.TRANSPORT.containedIn(metrics),
            NodesStatsMetrics.Metric.HTTP.containedIn(metrics),
            NodesStatsMetrics.Metric.BREAKER.containedIn(metrics),
            NodesStatsMetrics.Metric.SCRIPT.containedIn(metrics),
            NodesStatsMetrics.Metric.DISCOVERY.containedIn(metrics),
            NodesStatsMetrics.Metric.INGEST.containedIn(metrics),
            NodesStatsMetrics.Metric.ADAPTIVE_SELECTION.containedIn(metrics),
            NodesStatsMetrics.Metric.SCRIPT_CACHE.containedIn(metrics),
            NodesStatsMetrics.Metric.INDEXING_PRESSURE.containedIn(metrics),
            NodesStatsMetrics.Metric.REPOSITORIES.containedIn(metrics)
        );
    }

    public static class NodeStatsRequest extends TransportRequest {

        NodesStatsRequest request;

        public NodeStatsRequest(StreamInput in) throws IOException {
            super(in);
            request = new NodesStatsRequest(in);
        }

        NodeStatsRequest(NodesStatsRequest request) {
            this.request = request;
        }

        @Override
        public Task createTask(long id, String type, String action, TaskId parentTaskId, Map<String, String> headers) {
            return new CancellableTask(id, type, action, "", parentTaskId, headers) {
                @Override
                public String getDescription() {
                    return request.getDescription();
                }
            };
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }
}
