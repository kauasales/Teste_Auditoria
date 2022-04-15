/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.coordination;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.routing.RoutingTable;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.EqualsHashCodeTestUtils;
import org.junit.Before;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;

public class MasterHistoryTests extends ESTestCase {

    private ClusterState nullMasterClusterState;
    private ClusterState node1MasterClusterState;
    private ClusterState node2MasterClusterState;
    private ClusterState node3MasterClusterState;
    private static final String TEST_SOURCE = "test";

    @Before
    public void setup() throws Exception {
        String node1 = randomNodeId();
        String node2 = randomNodeId();
        String node3 = randomNodeId();
        nullMasterClusterState = createClusterState(null);
        node1MasterClusterState = createClusterState(node1);
        node2MasterClusterState = createClusterState(node2);
        node3MasterClusterState = createClusterState(node3);
    }

    public void testGetBasicUse() {
        var clusterService = mock(ClusterService.class);
        MasterHistory masterHistory = new MasterHistory(clusterService);
        assertNull(masterHistory.getCurrentMaster());
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, nullMasterClusterState));
        assertNull(masterHistory.getCurrentMaster());
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node1MasterClusterState, nullMasterClusterState));
        assertThat(masterHistory.getCurrentMaster(), equalTo(node1MasterClusterState.nodes().getMasterNode()));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node2MasterClusterState, node1MasterClusterState));
        assertThat(masterHistory.getCurrentMaster(), equalTo(node2MasterClusterState.nodes().getMasterNode()));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node3MasterClusterState, node2MasterClusterState));
        assertThat(masterHistory.getCurrentMaster(), equalTo(node3MasterClusterState.nodes().getMasterNode()));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node1MasterClusterState, node3MasterClusterState));
        assertThat(masterHistory.getCurrentMaster(), equalTo(node1MasterClusterState.nodes().getMasterNode()));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, node1MasterClusterState));
        assertNull(masterHistory.getCurrentMaster());
        assertThat(masterHistory.getMostRecentNonNullMaster(), equalTo(node1MasterClusterState.nodes().getMasterNode()));
        assertThat(masterHistory.getDistinctMastersSeen().size(), equalTo(3));
    }

    public void testHasMasterGoneNull() {
        var clusterService = mock(ClusterService.class);
        MasterHistory masterHistory = new MasterHistory(clusterService);
        long oneHourAgo = System.currentTimeMillis() - (60 * 60 * 1000);
        masterHistory.nowSupplier = () -> oneHourAgo;
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, nullMasterClusterState));
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node1MasterClusterState, nullMasterClusterState));
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, node1MasterClusterState));
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node1MasterClusterState, nullMasterClusterState));
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, node1MasterClusterState));
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node1MasterClusterState, nullMasterClusterState));
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, node1MasterClusterState));
        assertTrue(masterHistory.hasSameMasterGoneNullNTimes(3));
        masterHistory.nowSupplier = System::currentTimeMillis;
        assertFalse(masterHistory.hasSameMasterGoneNullNTimes(3));
    }

    public void testTime() {
        var clusterService = mock(ClusterService.class);
        MasterHistory masterHistory = new MasterHistory(clusterService);
        long oneHourAgo = System.currentTimeMillis() - (60 * 60 * 1000);
        masterHistory.nowSupplier = () -> oneHourAgo;
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, nullMasterClusterState));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node1MasterClusterState, nullMasterClusterState));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node2MasterClusterState, node1MasterClusterState));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node3MasterClusterState, node2MasterClusterState));
        assertThat(masterHistory.getCurrentMaster(), equalTo(node3MasterClusterState.nodes().getMasterNode()));
        assertThat(masterHistory.getDistinctMastersSeen().size(), equalTo(3));
        masterHistory.nowSupplier = System::currentTimeMillis;
        assertThat(masterHistory.getCurrentMaster(), equalTo(node3MasterClusterState.nodes().getMasterNode()));
        assertThat(masterHistory.getDistinctMastersSeen().size(), equalTo(1));
        assertTrue(masterHistory.hasSeenMasterInLastNSeconds(5));
    }

    public void testSerialization() throws IOException {
        var clusterService = mock(ClusterService.class);
        MasterHistory masterHistory = new MasterHistory(clusterService);
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, nullMasterClusterState, nullMasterClusterState));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node1MasterClusterState, nullMasterClusterState));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node2MasterClusterState, node1MasterClusterState));
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node3MasterClusterState, node2MasterClusterState));
        MasterHistory copy = copyWriteable(masterHistory, writableRegistry(), MasterHistory::new);
        assertEquals(masterHistory, copy);
        assertEquals(masterHistory.hashCode(), copy.hashCode());
        masterHistory.clusterChanged(new ClusterChangedEvent(TEST_SOURCE, node2MasterClusterState, node3MasterClusterState));
        assertNotEquals(masterHistory, copy);
        EqualsHashCodeTestUtils.checkEqualsAndHashCode(
            masterHistory,
            history -> copyWriteable(history, writableRegistry(), MasterHistory::new)
        );
    }

    private static String randomNodeId() {
        return UUID.randomUUID().toString();
    }

    private static ClusterState createClusterState(String masterNodeId) throws UnknownHostException {
        var routingTableBuilder = RoutingTable.builder();
        Metadata.Builder metadataBuilder = Metadata.builder();
        DiscoveryNodes.Builder nodesBuilder = DiscoveryNodes.builder();
        if (masterNodeId != null) {
            DiscoveryNode node = new DiscoveryNode(masterNodeId, new TransportAddress(InetAddress.getLocalHost(), 9200), Version.CURRENT);
            nodesBuilder.masterNodeId(masterNodeId);
            nodesBuilder.add(node);
        }
        return ClusterState.builder(new ClusterName("test-cluster"))
            .routingTable(routingTableBuilder.build())
            .metadata(metadataBuilder.build())
            .nodes(nodesBuilder)
            .build();
    }
}
