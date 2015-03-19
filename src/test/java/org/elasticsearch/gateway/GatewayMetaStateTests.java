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

package org.elasticsearch.gateway;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.routing.RoutingTable;
import org.elasticsearch.cluster.routing.allocation.AllocationService;
import org.elasticsearch.cluster.routing.allocation.decider.ClusterRebalanceAllocationDecider;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.test.ElasticsearchAllocationTestCase;
import org.junit.Test;

import java.util.Iterator;

import static org.elasticsearch.cluster.routing.ShardRoutingState.INITIALIZING;
import static org.elasticsearch.common.settings.ImmutableSettings.settingsBuilder;
import static org.hamcrest.Matchers.equalTo;

/**
 * Test IndexMetaState for master and data only nodes return correct list of indices to write
 * There are many parameters:
 * - meta state is not in memory
 * - meta state is in memory with old version/ new version
 * - meta state is in memory with new version
 * - version changed in cluster state event/ no change
 * - node is data only node
 * - node is master eligible
 * for data only nodes: shard initializing on shard
 */
public class GatewayMetaStateTests extends ElasticsearchAllocationTestCase {

    ClusterChangedEvent generateEvent(boolean initializing, boolean versionChanged) {
        //ridiculous settings to make sure we don't run into uninitialized because fo default
        AllocationService strategy = createAllocationService(settingsBuilder()
                .put("cluster.routing.allocation.concurrent_recoveries", 100)
                .put(ClusterRebalanceAllocationDecider.CLUSTER_ROUTING_ALLOCATION_ALLOW_REBALANCE, "always")
                .put("cluster.routing.allocation.cluster_concurrent_rebalance", 100)
                .put("cluster.routing.allocation.node_initial_primaries_recoveries", 100)
                .build());
        ClusterState newClusterState, previousClusterState;
        MetaData metaDataOldClusterState = MetaData.builder()
                .put(IndexMetaData.builder("test").settings(settings(Version.CURRENT)).numberOfShards(5).numberOfReplicas(2))
                .build();

        RoutingTable routingTableOldClusterState = RoutingTable.builder()
                .addAsNew(metaDataOldClusterState.index("test"))
                .build();

        // assign all shards to node1
        ClusterState init = ClusterState.builder(org.elasticsearch.cluster.ClusterName.DEFAULT)
                .metaData(metaDataOldClusterState)
                .routingTable(routingTableOldClusterState)
                .nodes(DiscoveryNodes.builder().put(newNode("node1")).localNodeId("node1"))
                .build();
        // new cluster state will have initializing shards on node 1
        RoutingTable routingTableNewClusterState = strategy.reroute(init).routingTable();
        if (initializing == false) {
            // pretend all initialized, nothing happened
            ClusterState temp = ClusterState.builder(init).routingTable(routingTableNewClusterState).metaData(metaDataOldClusterState).build();
            routingTableNewClusterState = strategy.applyStartedShards(temp, temp.getRoutingNodes().shardsWithState(INITIALIZING)).routingTable();
            routingTableOldClusterState = routingTableNewClusterState;

        } else {
            // nothing to do, we have one routing table with unassigned and one with initializing
        }

        // create new meta data either with version changed or not
        MetaData metaDataNewClusterState = MetaData.builder()
                .put(init.metaData().index("test"), versionChanged)
                .build();

        // create the cluster states with meta data and routing tables as computed before
        previousClusterState = ClusterState.builder(init)
                .metaData(metaDataOldClusterState)
                .routingTable(routingTableOldClusterState)
                .nodes(DiscoveryNodes.builder().put(newNode("node1")).localNodeId("node1"))
                .build();
        newClusterState = ClusterState.builder(previousClusterState).routingTable(routingTableNewClusterState).metaData(metaDataNewClusterState).version(previousClusterState.getVersion() + 1).build();

        ClusterChangedEvent event = new ClusterChangedEvent("test", newClusterState, previousClusterState);
        assertThat(event.state().version(), equalTo(event.previousState().version() + 1));
        return event;
    }

    public void assertState(ClusterChangedEvent event,
                            boolean stateInMemory,
                            boolean masterEligible,
                            boolean expectMetaData) throws Exception {
        logger.debug("Testing combination:");
        logger.debug("stateInMemory: {}", stateInMemory);
        logger.debug("masterEligible: {}", masterEligible);
        logger.debug("expectMetaData: {}", expectMetaData);


        MetaData inMemoryMetaData = null;
        if (stateInMemory) {
            inMemoryMetaData = event.previousState().metaData();
        }
        Iterator<GatewayMetaState.IndexMetaWriteInfo> indices;
        if (masterEligible) {
            indices = GatewayMetaState.filterStatesOnMaster(event.state(), inMemoryMetaData).iterator();
        } else {
            indices = GatewayMetaState.filterStateOnDataNode(event, inMemoryMetaData).iterator();
        }
        if (expectMetaData) {
            assertThat(indices.hasNext(), equalTo(true));
            assertThat(indices.next().getNewMetaData().index(), equalTo("test"));
            assertThat(indices.hasNext(), equalTo(false));
        } else {
            assertThat(indices.hasNext(), equalTo(false));
        }
    }

    @Test
    public void testVersionChangeIsAlwaysWritten() throws Exception {
        // test that version changes are always written
        boolean initializing = randomBoolean();
        boolean versionChanged = true;
        ClusterChangedEvent event = generateEvent(initializing, versionChanged);
        boolean stateInMemory = randomBoolean();
        boolean masterEligible = randomBoolean();
        boolean expectMetaData = true;
        assertState(event,
                stateInMemory, masterEligible, expectMetaData);
    }

    @Test
    public void testNewShardsAlwaysWritten() throws Exception {
        // make sure new shards on data only node always written
        boolean initializing = true;
        boolean versionChanged = randomBoolean();
        ClusterChangedEvent event = generateEvent(initializing, versionChanged);
        boolean stateInMemory = randomBoolean();
        boolean masterEligible = false;
        boolean expectMetaData = true;
        assertState(event,
                stateInMemory, masterEligible,
                expectMetaData);
    }

    @Test
    public void testAllUpToDateNothingWritten() throws Exception {
        // make sure state is not written again if we wrote already
        boolean initializing = false;
        boolean versionChanged = false;
        ClusterChangedEvent event = generateEvent(initializing, versionChanged);
        boolean stateInMemory = true;
        boolean masterEligible = randomBoolean();
        boolean expectMetaData = false;
        assertState(event,
                stateInMemory, masterEligible, expectMetaData);
    }

    @Test
    public void testOnlyWriteIfNoShardsAllocatedBefore() throws Exception {
        ClusterChangedEvent event = generateEvent(true, false);
        ClusterChangedEvent newEventWithNothingChanged = new ClusterChangedEvent("test cluster state", event.state(), event.state());
        boolean stateInMemory = true;
        boolean masterEligible = randomBoolean();
        boolean expectMetaData = false;
        assertState(newEventWithNothingChanged,
                stateInMemory, masterEligible, expectMetaData);
    }
}
