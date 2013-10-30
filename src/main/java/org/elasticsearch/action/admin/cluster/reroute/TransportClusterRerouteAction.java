/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

package org.elasticsearch.action.admin.cluster.reroute;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.master.TransportMasterNodeOperationAction;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ack.ClusterStateUpdateListener;
import org.elasticsearch.cluster.metadata.MetaDataClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

/**
 * Cluster reroute action
 */
public class TransportClusterRerouteAction extends TransportMasterNodeOperationAction<ClusterRerouteRequest, ClusterRerouteResponse> {

    private final MetaDataClusterService metaDataClusterService;

    @Inject
    public TransportClusterRerouteAction(Settings settings, TransportService transportService, ClusterService clusterService, ThreadPool threadPool, MetaDataClusterService metaDataClusterService) {
        super(settings, transportService, clusterService, threadPool);
        this.metaDataClusterService = metaDataClusterService;
    }

    @Override
    protected String executor() {
        // we go async right away
        return ThreadPool.Names.SAME;
    }

    @Override
    protected String transportAction() {
        return ClusterRerouteAction.NAME;
    }

    @Override
    protected ClusterRerouteRequest newRequest() {
        return new ClusterRerouteRequest();
    }

    @Override
    protected ClusterRerouteResponse newResponse() {
        return new ClusterRerouteResponse();
    }

    @Override
    protected void masterOperation(final ClusterRerouteRequest request, final ClusterState state, final ActionListener<ClusterRerouteResponse> listener) throws ElasticSearchException {
        ClusterRerouteClusterStateUpdateRequest updateRequest = new ClusterRerouteClusterStateUpdateRequest(request.commands, request.dryRun())
                .ackTimeout(request.timeout()).masterNodeTimeout(request.masterNodeTimeout());

        metaDataClusterService.reroute(updateRequest, new ClusterStateUpdateListener<ClusterRerouteClusterStateUpdateResponse>() {
            @Override
            public void onResponse(ClusterRerouteClusterStateUpdateResponse response) {
                listener.onResponse(new ClusterRerouteResponse(response.isAcknowledged(), response.clusterState()));
            }

            @Override
            public void onFailure(Throwable t) {
                listener.onFailure(t);
            }
        });
    }
}