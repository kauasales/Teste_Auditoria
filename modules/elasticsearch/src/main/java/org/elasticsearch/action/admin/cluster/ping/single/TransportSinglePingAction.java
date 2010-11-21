/*
 * Licensed to Elastic Search and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Elastic Search licenses this
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

package org.elasticsearch.action.admin.cluster.ping.single;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.action.TransportActions;
import org.elasticsearch.action.support.single.shard.TransportShardSingleOperationAction;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

/**
 * @author kimchy (shay.banon)
 */
public class TransportSinglePingAction extends TransportShardSingleOperationAction<SinglePingRequest, SinglePingResponse> {

    @Inject public TransportSinglePingAction(Settings settings, ThreadPool threadPool, ClusterService clusterService, TransportService transportService) {
        super(settings, threadPool, clusterService, transportService);
    }

    @Override protected String transportAction() {
        return TransportActions.Admin.Cluster.Ping.SINGLE;
    }

    @Override protected String transportShardAction() {
        return "/cluster/ping/single/shard";
    }

    @Override protected SinglePingResponse shardOperation(SinglePingRequest request, int shardId) throws ElasticSearchException {
        return new SinglePingResponse();
    }

    @Override protected SinglePingRequest newRequest() {
        return new SinglePingRequest();
    }

    @Override protected SinglePingResponse newResponse() {
        return new SinglePingResponse();
    }
}