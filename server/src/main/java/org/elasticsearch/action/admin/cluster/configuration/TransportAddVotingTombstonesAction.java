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
package org.elasticsearch.action.admin.cluster.configuration;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.master.TransportMasterNodeAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterState.Builder;
import org.elasticsearch.cluster.ClusterStateObserver;
import org.elasticsearch.cluster.ClusterStateObserver.Listener;
import org.elasticsearch.cluster.ClusterStateUpdateTask;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.threadpool.ThreadPool.Names;
import org.elasticsearch.transport.TransportService;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class TransportAddVotingTombstonesAction extends TransportMasterNodeAction<AddVotingTombstonesRequest, AddVotingTombstonesResponse> {

    public static final Setting<Integer> MAXIMUM_VOTING_TOMBSTONES_SETTING
        = Setting.intSetting("cluster.max_voting_tombstones", 10, 1, Property.Dynamic, Property.NodeScope);

    @Inject
    public TransportAddVotingTombstonesAction(TransportService transportService, ClusterService clusterService, ThreadPool threadPool,
                                              ActionFilters actionFilters, IndexNameExpressionResolver indexNameExpressionResolver) {
        super(AddVotingTombstonesAction.NAME, transportService, clusterService, threadPool, actionFilters, AddVotingTombstonesRequest::new,
            indexNameExpressionResolver);
    }

    @Override
    protected String executor() {
        return Names.SAME;
    }

    @Override
    protected AddVotingTombstonesResponse newResponse() {
        throw new UnsupportedOperationException("usage of Streamable is to be replaced by Writeable");
    }

    @Override
    protected AddVotingTombstonesResponse read(StreamInput in) throws IOException {
        return new AddVotingTombstonesResponse(in);
    }

    @Override
    protected void masterOperation(AddVotingTombstonesRequest request, ClusterState state,
                                   ActionListener<AddVotingTombstonesResponse> listener) throws Exception {

        clusterService.getMasterService().submitStateUpdateTask("add-voting-tombstones", new ClusterStateUpdateTask() {

            final ClusterStateObserver observer
                = new ClusterStateObserver(clusterService, request.getTimeout(), logger, threadPool.getThreadContext());

            private Set<DiscoveryNode> resolvedNodes;

            @Override
            public ClusterState execute(ClusterState currentState) {
                final DiscoveryNodes allNodes = currentState.nodes();
                assert resolvedNodes == null : resolvedNodes;
                resolvedNodes = Arrays.stream(allNodes.resolveNodes(request.getNodeDescriptions()))
                    .map(allNodes::get).filter(DiscoveryNode::isMasterNode).collect(Collectors.toSet());

                if (resolvedNodes.isEmpty()) {
                    throw new IllegalArgumentException("add voting tombstones request for " + Arrays.asList(request.getNodeDescriptions())
                        + " matched no master-eligible nodes");
                }

                resolvedNodes.removeIf(n -> currentState.getVotingTombstones().contains(n));
                if (resolvedNodes.isEmpty()) {
                    throw new IllegalArgumentException("add voting tombstones request for " + Arrays.asList(request.getNodeDescriptions())
                        + " matched no master-eligible nodes that do not already have tombstones");
                }

                final int oldTombstoneCount = currentState.getVotingTombstones().size();
                final int newTombstoneCount = resolvedNodes.size();
                final int maxTombstoneCount = MAXIMUM_VOTING_TOMBSTONES_SETTING.get(currentState.metaData().settings());
                if (oldTombstoneCount + newTombstoneCount > maxTombstoneCount) {
                    throw new IllegalArgumentException("add voting tombstones request for " + Arrays.asList(request.getNodeDescriptions())
                        + " would add [" + newTombstoneCount + "] voting tombstones to the existing [" + oldTombstoneCount
                        + "] which would exceed the maximum of [" + maxTombstoneCount + "] set by ["
                        + MAXIMUM_VOTING_TOMBSTONES_SETTING.getKey() + "]");
                }

                final Builder builder = ClusterState.builder(currentState);
                resolvedNodes.forEach(builder::addVotingTombstone);
                final ClusterState newState = builder.build();
                assert newState.getVotingTombstones().size() <= maxTombstoneCount;
                return newState;
            }

            @Override
            public void onFailure(String source, Exception e) {
                listener.onFailure(e);
            }

            @Override
            public void clusterStateProcessed(String source, ClusterState oldState, ClusterState newState) {

                final Set<String> resolvedNodeIds = resolvedNodes.stream().map(DiscoveryNode::getId).collect(Collectors.toSet());

                final Predicate<ClusterState> allNodesRemoved = new Predicate<ClusterState>() {
                    @Override
                    public boolean test(ClusterState clusterState) {
                        final Set<String> votingNodeIds = clusterState.getLastCommittedConfiguration().getNodeIds();
                        return resolvedNodeIds.stream().anyMatch(votingNodeIds::contains) == false;
                    }

                    @Override
                    public String toString() {
                        return "withdrawal of votes from " + resolvedNodes;
                    }
                };

                final Listener clusterStateListener = new Listener() {
                    @Override
                    public void onNewClusterState(ClusterState state) {
                        listener.onResponse(new AddVotingTombstonesResponse(state.getVotingTombstones()));
                    }

                    @Override
                    public void onClusterServiceClose() {
                        listener.onFailure(new ElasticsearchException("cluster service closed while waiting for " + allNodesRemoved));
                    }

                    @Override
                    public void onTimeout(TimeValue timeout) {
                        listener.onFailure(new ElasticsearchTimeoutException("timed out waiting for " + allNodesRemoved));
                    }
                };

                if (allNodesRemoved.test(newState)) {
                    clusterStateListener.onNewClusterState(newState);
                } else {
                    observer.waitForNextChange(clusterStateListener, allNodesRemoved);
                }
            }
        });
    }

    @Override
    protected ClusterBlockException checkBlock(AddVotingTombstonesRequest request, ClusterState state) {
        return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
    }
}
