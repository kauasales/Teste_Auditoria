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

package org.elasticsearch.client.action.admin.cluster.health;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthStatus;
import org.elasticsearch.client.ClusterAdminClient;
import org.elasticsearch.client.action.admin.cluster.support.BaseClusterRequestBuilder;
import org.elasticsearch.common.unit.TimeValue;

/**
 * @author kimchy (shay.banon)
 */
public class ClusterHealthRequestBuilder extends BaseClusterRequestBuilder<ClusterHealthRequest, ClusterHealthResponse> {

    public ClusterHealthRequestBuilder(ClusterAdminClient clusterClient) {
        super(clusterClient, new ClusterHealthRequest());
    }

    public ClusterHealthRequestBuilder setIndices(String... indices) {
        request.indices(indices);
        return this;
    }

    public ClusterHealthRequestBuilder setTimeout(TimeValue timeout) {
        request.timeout(timeout);
        return this;
    }

    public ClusterHealthRequestBuilder setTimeout(String timeout) {
        request.timeout(timeout);
        return this;
    }

    public ClusterHealthRequestBuilder setWaitForStatus(ClusterHealthStatus waitForStatus) {
        request.waitForStatus(waitForStatus);
        return this;
    }

    public ClusterHealthRequestBuilder setWaitForGreenStatus() {
        request.waitForGreenStatus();
        return this;
    }

    public ClusterHealthRequestBuilder setWaitForYellowStatus() {
        request.waitForYellowStatus();
        return this;
    }

    public ClusterHealthRequestBuilder setWaitForRelocatingShards(int waitForRelocatingShards) {
        request.waitForRelocatingShards(waitForRelocatingShards);
        return this;
    }

    public ClusterHealthRequestBuilder setWaitForActiveShards(int waitForActiveShards) {
        request.waitForActiveShards(waitForActiveShards);
        return this;
    }

    @Override protected void doExecute(ActionListener<ClusterHealthResponse> listener) {
        client.health(request, listener);
    }
}
