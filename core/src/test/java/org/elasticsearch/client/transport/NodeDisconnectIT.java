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
package org.elasticsearch.client.transport;

import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.transport.TransportService;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@ESIntegTestCase.SuppressNetworkMode
public class NodeDisconnectIT  extends ESIntegTestCase {

    public void testNotifyOnDisconnect() throws IOException {
        internalCluster().ensureAtLeastNumDataNodes(2);

        final Set<DiscoveryNode> disconnectedNodes = Collections.synchronizedSet(new HashSet<DiscoveryNode>());
        TransportClient client = TransportClient.builder().settings(Settings.builder()
            .put("cluster.name", internalCluster().getClusterName())
            .put("path.home", createTempDir().toString())
            .put("transport.type", "local")
            .build()).setHostFailedListener(new TransportClient.HostFailureListener() {
            @Override
            public void onNodeDisconnected(DiscoveryNode node, Throwable ex) {
                disconnectedNodes.add(node);
            }
        }).build();
        try {
            for (TransportService service : internalCluster().getInstances(TransportService.class)) {
                client.addTransportAddress(service.boundAddress().publishAddress());
            }
            internalCluster().stopRandomDataNode();
            for (int i = 0; i < 20; i++) { // fire up requests such that we hit the node and pass it to the listener
                client.admin().cluster().prepareState().get();
            }
            assertEquals(1, disconnectedNodes.size());
        } finally {
            client.close();
        }
        assertEquals(1, disconnectedNodes.size());
    }

    public void testNotifyOnDisconnectInSniffer() throws IOException {
        internalCluster().ensureAtLeastNumDataNodes(2);

        final Set<DiscoveryNode> disconnectedNodes = Collections.synchronizedSet(new HashSet<DiscoveryNode>());
        TransportClient client = TransportClient.builder().settings(Settings.builder()
            .put("cluster.name", internalCluster().getClusterName())
            .put("path.home", createTempDir().toString())
            .put("transport.type", "local")
            .build()).setHostFailedListener(new TransportClient.HostFailureListener() {
            @Override
            public void onNodeDisconnected(DiscoveryNode node, Throwable ex) {
                disconnectedNodes.add(node);
            }
        }).build();
        try {
            int numNodes = 0;
            for (TransportService service : internalCluster().getInstances(TransportService.class)) {
                numNodes++;
                client.addTransportAddress(service.boundAddress().publishAddress());
            }
            Set<TransportAddress> discoveryNodes = new HashSet<>();
            for (DiscoveryNode node : client.connectedNodes()) {
                discoveryNodes.add(node.getAddress());
            }
            assertEquals(numNodes, discoveryNodes.size());
            assertEquals(0, disconnectedNodes.size());
            internalCluster().stopRandomDataNode();
            client.getNodesService().doSample();
            assertEquals(1, disconnectedNodes.size());
            assertTrue(discoveryNodes.contains(disconnectedNodes.iterator().next().getAddress()));
        } finally {
            client.close();
        }
        assertEquals(1, disconnectedNodes.size());
    }
}
