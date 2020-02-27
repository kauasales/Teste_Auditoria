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

package org.elasticsearch.action.admin.indices.dangling;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.master.TransportMasterNodeAction;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.AckedClusterStateUpdateTask;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.metadata.IndexGraveyard;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.Index;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implements the deletion of a dangling index. When handling a {@link DeleteDanglingIndexAction},
 * this class first checks that such a dangling index exists. It then submits a cluster state update
 * to add the index to the index graveyard.
 */
public class TransportDeleteDanglingIndexAction extends TransportMasterNodeAction<DeleteDanglingIndexRequest, DeleteDanglingIndexResponse> {
    private static final Logger logger = LogManager.getLogger(TransportDeleteDanglingIndexAction.class);

    private final Settings settings;
    private final NodeClient nodeClient;

    @Inject
    public TransportDeleteDanglingIndexAction(
        TransportService transportService,
        ClusterService clusterService,
        ThreadPool threadPool,
        ActionFilters actionFilters,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Settings settings,
        NodeClient nodeClient
    ) {
        super(
            DeleteDanglingIndexAction.NAME,
            transportService,
            clusterService,
            threadPool,
            actionFilters,
            DeleteDanglingIndexRequest::new,
            indexNameExpressionResolver
        );
        this.settings = settings;
        this.nodeClient = nodeClient;
    }

    @Override
    protected String executor() {
        return ThreadPool.Names.GENERIC;
    }

    @Override
    protected DeleteDanglingIndexResponse read(StreamInput in) throws IOException {
        return new DeleteDanglingIndexResponse(in);
    }

    @Override
    protected void masterOperation(
        Task task,
        DeleteDanglingIndexRequest deleteRequest,
        ClusterState state,
        ActionListener<DeleteDanglingIndexResponse> deleteListener
    ) throws Exception {
        findDanglingIndex(deleteRequest.getIndexUUID(), new ActionListener<>() {

            @Override
            public void onResponse(Index indexToDelete) {
                // This flag is checked at this point so that we always check that the supplied index ID
                // does correspond to a dangling index.
                if (deleteRequest.isAcceptDataLoss() == false) {
                    deleteListener.onFailure(new IllegalArgumentException("accept_data_loss must be set to true"));
                    return;
                }

                String indexName = indexToDelete.getName();

                final ActionListener<DeleteDanglingIndexResponse> clusterStateUpdatedListener = new ActionListener<>() {
                    @Override
                    public void onResponse(DeleteDanglingIndexResponse response) {
                        deleteListener.onResponse(response);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        logger.debug("Failed to delete dangling index [{}]" + indexName, e);
                        deleteListener.onFailure(e);
                    }
                };

                clusterService.submitStateUpdateTask(
                    "delete-dangling-index " + indexName,
                    new AckedClusterStateUpdateTask<>(deleteRequest, clusterStateUpdatedListener) {

                        @Override
                        protected DeleteDanglingIndexResponse newResponse(boolean acknowledged) {
                            return new DeleteDanglingIndexResponse(acknowledged);
                        }

                        @Override
                        public ClusterState execute(final ClusterState currentState) {
                            return deleteDanglingIndex(currentState, indexToDelete);
                        }
                    }
                );
            }

            @Override
            public void onFailure(Exception e) {
                logger.debug("Failed to list dangling indices", e);
                deleteListener.onFailure(e);
            }
        });
    }

    private ClusterState deleteDanglingIndex(ClusterState currentState, Index indexToDelete) {
        final MetaData meta = currentState.metaData();

        MetaData.Builder metaDataBuilder = MetaData.builder(meta);

        final IndexGraveyard.Builder graveyardBuilder = IndexGraveyard.builder(metaDataBuilder.indexGraveyard());

        final IndexGraveyard newGraveyard = graveyardBuilder.addTombstone(indexToDelete).build(settings);
        metaDataBuilder.indexGraveyard(newGraveyard);

        return ClusterState.builder(currentState).metaData(metaDataBuilder.build()).build();
    }

    @Override
    protected ClusterBlockException checkBlock(DeleteDanglingIndexRequest request, ClusterState state) {
        return null;
    }

    private void findDanglingIndex(String indexUUID, ActionListener<Index> listener) {
        this.nodeClient.execute(FindDanglingIndexAction.INSTANCE, new FindDanglingIndexRequest(indexUUID), new ActionListener<>() {
            @Override
            public void onResponse(FindDanglingIndexResponse response) {
                if (response.hasFailures()) {
                    final String nodeIds = response.failures().stream().map(FailedNodeException::nodeId).collect(Collectors.joining(","));
                    ElasticsearchException e = new ElasticsearchException("Failed to query nodes [" + nodeIds + "]");

                    for (FailedNodeException failure : response.failures()) {
                        logger.error("Failed to query node [" + failure.nodeId() + "]", failure);
                        e.addSuppressed(failure);
                    }

                    listener.onFailure(e);
                    return;
                }

                final List<NodeFindDanglingIndexResponse> nodes = response.getNodes();

                for (NodeFindDanglingIndexResponse nodeResponse : nodes) {
                    for (IndexMetaData danglingIndexMetaData : nodeResponse.getDanglingIndexMetaData()) {
                        if (danglingIndexMetaData.getIndexUUID().equals(indexUUID)) {
                            listener.onResponse(danglingIndexMetaData.getIndex());
                            return;
                        }
                    }
                }

                listener.onFailure(new IllegalArgumentException("No dangling index found for UUID [" + indexUUID + "]"));
            }

            @Override
            public void onFailure(Exception exp) {
                listener.onFailure(exp);
            }
        });
    }
}
