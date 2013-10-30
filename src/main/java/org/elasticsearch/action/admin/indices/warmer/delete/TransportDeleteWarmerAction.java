/*
 * Licensed to Elastic Search and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Elastic Search licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.action.admin.indices.warmer.delete;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.master.TransportMasterNodeOperationAction;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ack.ClusterStateUpdateListener;
import org.elasticsearch.cluster.ack.ClusterStateUpdateResponse;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.MetaDataWarmersService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

/**
 * Delete index warmer.
 */
public class TransportDeleteWarmerAction extends TransportMasterNodeOperationAction<DeleteWarmerRequest, DeleteWarmerResponse> {

    private final MetaDataWarmersService metaDataWarmersService;

    @Inject
    public TransportDeleteWarmerAction(Settings settings, TransportService transportService, ClusterService clusterService, ThreadPool threadPool, MetaDataWarmersService metaDataWarmersService) {
        super(settings, transportService, clusterService, threadPool);
        this.metaDataWarmersService = metaDataWarmersService;
    }

    @Override
    protected String executor() {
        // we go async right away
        return ThreadPool.Names.SAME;
    }

    @Override
    protected String transportAction() {
        return DeleteWarmerAction.NAME;
    }

    @Override
    protected DeleteWarmerRequest newRequest() {
        return new DeleteWarmerRequest();
    }

    @Override
    protected DeleteWarmerResponse newResponse() {
        return new DeleteWarmerResponse();
    }

    @Override
    protected void doExecute(DeleteWarmerRequest request, ActionListener<DeleteWarmerResponse> listener) {
        // update to concrete indices
        request.indices(clusterService.state().metaData().concreteIndices(request.indices()));
        super.doExecute(request, listener);
    }

    @Override
    protected ClusterBlockException checkBlock(DeleteWarmerRequest request, ClusterState state) {
        return state.blocks().indicesBlockedException(ClusterBlockLevel.METADATA, request.indices());
    }

    @Override
    protected void masterOperation(final DeleteWarmerRequest request, final ClusterState state, final ActionListener<DeleteWarmerResponse> listener) throws ElasticSearchException {

        DeleteWarmerClusterStateUpdateRequest deleteWarmerRequest = new DeleteWarmerClusterStateUpdateRequest(request.name(), request.indices())
                .ackTimeout(request.timeout()).masterNodeTimeout(request.masterNodeTimeout());

        metaDataWarmersService.deleteWarmer(deleteWarmerRequest, new ClusterStateUpdateListener<ClusterStateUpdateResponse>() {
            @Override
            public void onResponse(ClusterStateUpdateResponse response) {
                listener.onResponse(new DeleteWarmerResponse(response.isAcknowledged()));
            }

            @Override
            public void onFailure(Throwable t) {
                listener.onFailure(t);
            }
        });
    }
}
