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

package org.elasticsearch.action.admin.cluster.allocation;

import org.apache.lucene.util.IOUtils;
import org.elasticsearch.action.support.ActiveShardCount;
import org.elasticsearch.cluster.ClusterInfo;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.routing.ShardRoutingState;
import org.elasticsearch.cluster.routing.UnassignedInfo;
import org.elasticsearch.cluster.routing.UnassignedInfo.AllocationStatus;
import org.elasticsearch.cluster.routing.UnassignedInfo.Reason;
import org.elasticsearch.cluster.routing.allocation.AllocateUnassignedDecision;
import org.elasticsearch.cluster.routing.allocation.AllocationDecision;
import org.elasticsearch.cluster.routing.allocation.MoveDecision;
import org.elasticsearch.cluster.routing.allocation.NodeAllocationResult;
import org.elasticsearch.cluster.routing.allocation.decider.Decision;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.InternalTestCluster;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.elasticsearch.cluster.routing.allocation.decider.MaxRetryAllocationDecider.SETTING_ALLOCATION_MAX_RETRY;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.startsWith;

/**
 * Tests for the cluster allocation explanation
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0)
public final class ClusterAllocationExplainIT extends ESIntegTestCase {

    public void testUnassignedPrimaryWithExistingIndex() throws Exception {
        logger.info("--> starting 2 nodes");
        internalCluster().startNodes(2);
        ensureStableCluster(2);

        logger.info("--> creating an index with 1 primary, 0 replicas");
        createIndexAndIndexData(1, 0);

        logger.info("--> stopping the node with the primary");
        internalCluster().stopRandomNode(InternalTestCluster.nameFilter(primaryNodeName()));
        ensureStableCluster(1);

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(true, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertTrue(isPrimary);

        // verify current node info
        assertNotEquals(ShardRoutingState.STARTED, shardState);
        assertNull(currentNode);

        // verify unassigned info
        assertNotNull(unassignedInfo);
        assertEquals(Reason.NODE_LEFT, unassignedInfo.getReason());
        assertTrue(unassignedInfo.getLastAllocationStatus() == AllocationStatus.FETCHING_SHARD_DATA
                       || unassignedInfo.getLastAllocationStatus() == AllocationStatus.NO_VALID_SHARD_COPY);

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 1);

        // very decision objects
        assertTrue(allocateDecision.isDecisionTaken());
        assertFalse(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.NO_VALID_SHARD_COPY, allocateDecision.getAllocationDecision());
        assertEquals("cannot allocate because a previous copy of the primary shard existed but could not be found",
            allocateDecision.getExplanation());
        assertNull(allocateDecision.getAllocationId());
        assertNull(allocateDecision.getTargetNode());
        assertEquals(0L, allocateDecision.getConfiguredDelayInMillis());
        assertEquals(0L, allocateDecision.getRemainingDelayInMillis());
        assertEquals(0, allocateDecision.getNodeDecisions().size());
    }

    public void testUnassignedPrimaryDueToFailedInitialization() throws Exception {
        logger.info("--> starting 2 nodes");
        internalCluster().startNodes(2);
        ensureStableCluster(2);

        logger.info("--> creating an index with 1 primary, 0 replicas");
        // set max retries to 1 to speed the process up
        createIndexAndIndexData(1, 0, Settings.builder().put(SETTING_ALLOCATION_MAX_RETRY.getKey(), 1).build(), true);
        Index index = resolveIndex("idx");
        String primaryNode = primaryNodeName();
        Path shardPath = internalCluster().getInstance(NodeEnvironment.class, primaryNode).availableShardPaths(new ShardId(index, 0))[0];

        logger.info("--> stopping the node with the primary [{}]", primaryNode);
        internalCluster().stopRandomNode(InternalTestCluster.nameFilter(primaryNode));
        ensureStableCluster(1);

        logger.info("--> deleting a cfs file to make the shard copy corrupt");
        IOUtils.rm(shardPath.resolve("index/_0.cfs"));

        logger.info("--> restarting the node with the primary [{}]", primaryNode);
        internalCluster().startDataOnlyNode(Settings.builder().put("node.name", primaryNode).build());
        ensureStableCluster(2);
        // wait until shard has attempted to initialize max number of retries
        assertBusy(() -> {
            UnassignedInfo unassignedInfo = client().admin().cluster().prepareAllocationExplain()
                .setIndex("idx").setShard(0).setPrimary(true).get().getExplanation().getUnassignedInfo();
            assertNotNull(unassignedInfo);
            assertThat(unassignedInfo.getNumFailedAllocations(), greaterThanOrEqualTo(1));
        });

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(true, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertTrue(isPrimary);

        // verify current node info
        assertNotEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNull(currentNode);

        // verify unassigned info
        assertNotNull(unassignedInfo);
        assertEquals(Reason.ALLOCATION_FAILED, unassignedInfo.getReason());

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 2);

        // very decision objects
        assertTrue(allocateDecision.isDecisionTaken());
        assertFalse(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.NO, allocateDecision.getAllocationDecision());
        assertEquals("cannot allocate because allocation is not permitted to any of the nodes that hold an in-sync shard copy",
            allocateDecision.getExplanation());
        assertNull(allocateDecision.getAllocationId());
        assertNull(allocateDecision.getTargetNode());
        assertEquals(0L, allocateDecision.getConfiguredDelayInMillis());
        assertEquals(0L, allocateDecision.getRemainingDelayInMillis());
        assertEquals(1, allocateDecision.getNodeDecisions().size());
        NodeAllocationResult result = allocateDecision.getNodeDecisions().get(0);
        assertNotNull(result.getNode());
        assertEquals(AllocationDecision.NO, result.getNodeDecision());
        assertTrue(result.getShardStoreInfo().isInSync());
        assertNotNull(result.getShardStoreInfo().getAllocationId());
        if (includeYesDecisions) {
            assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(1));
        } else {
            assertEquals(1, result.getCanAllocateDecision().getDecisions().size());
        }
        for (Decision d : result.getCanAllocateDecision().getDecisions()) {
            assertEquals(d.label().equals("max_retry") ? Decision.Type.NO : Decision.Type.YES, d.type());
            assertNotNull(d.getExplanation());
            if (d.label().equals("max_retry")) {
                assertThat(d.getExplanation(), startsWith("shard has exceeded the maximum number of retries [1] on failed allocation " +
                    "attempts - manually call [/_cluster/reroute?retry_failed=true] to retry"));
            }
        }
    }

    public void testUnassignedReplicaDelayedAllocation() throws Exception {
        logger.info("--> starting 3 nodes");
        internalCluster().startNodes(3);
        ensureStableCluster(3);

        logger.info("--> creating an index with 1 primary, 1 replica");
        createIndexAndIndexData(1, 1);
        logger.info("--> stopping the node with the replica");
        internalCluster().stopRandomNode(InternalTestCluster.nameFilter(replicaNodeName()));
        ensureStableCluster(2);

        logger.info("--> observing delayed allocation...");
        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(false, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertFalse(isPrimary);

        // verify current node info
        assertNotEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNull(currentNode);

        // verify unassigned info
        assertNotNull(unassignedInfo);
        assertEquals(Reason.NODE_LEFT, unassignedInfo.getReason());
        assertEquals(AllocationStatus.NO_ATTEMPT, unassignedInfo.getLastAllocationStatus());

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 2);

        // verify decision objects
        assertTrue(allocateDecision.isDecisionTaken());
        assertFalse(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.DELAYED_ALLOCATION, allocateDecision.getAllocationDecision());
        assertThat(allocateDecision.getExplanation(), startsWith("cannot allocate because the cluster is still waiting"));
        assertThat(allocateDecision.getExplanation(), containsString(
            "despite being allowed to allocate the shard to at least one other node"));
        assertNull(allocateDecision.getAllocationId());
        assertNull(allocateDecision.getTargetNode());
        assertEquals(60000L, allocateDecision.getConfiguredDelayInMillis());
        assertThat(allocateDecision.getRemainingDelayInMillis(), greaterThan(0L));
        assertEquals(2, allocateDecision.getNodeDecisions().size());
        String primaryNodeName = primaryNodeName();
        for (NodeAllocationResult result : allocateDecision.getNodeDecisions()) {
            assertNotNull(result.getNode());
            boolean nodeHoldingPrimary = result.getNode().getName().equals(primaryNodeName);
            if (nodeHoldingPrimary) {
                // shouldn't be able to allocate to the same node as the primary, the same shard decider should say no
                assertEquals(AllocationDecision.NO, result.getNodeDecision());
                assertThat(result.getShardStoreInfo().getMatchingBytes(), greaterThan(0L));
            } else {
                assertEquals(AllocationDecision.YES, result.getNodeDecision());
                assertNull(result.getShardStoreInfo());
            }
            if (includeYesDecisions) {
                assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(1));
            } else {
                // if we are not including YES decisions, then the node holding the primary should have 1 NO decision,
                // the other node should have zero NO decisions
                assertEquals(nodeHoldingPrimary ? 1 : 0, result.getCanAllocateDecision().getDecisions().size());
            }
            for (Decision d : result.getCanAllocateDecision().getDecisions()) {
                if (d.label().equals("same_shard") && nodeHoldingPrimary) {
                    assertEquals(Decision.Type.NO, d.type());
                    assertThat(d.getExplanation(), startsWith(
                        "the shard cannot be allocated to the same node on which a copy of the shard already exists"));
                } else {
                    assertEquals(Decision.Type.YES, d.type());
                    assertNotNull(d.getExplanation());
                }
            }
        }
    }

    public void testUnassignedReplicaWithPriorCopy() throws Exception {
        logger.info("--> starting 3 nodes");
        List<String> nodes = internalCluster().startNodes(3);
        ensureStableCluster(3);

        logger.info("--> creating an index with 1 primary and 1 replica");
        createIndexAndIndexData(1, 1);
        String primaryNodeName = primaryNodeName();
        nodes.remove(primaryNodeName);

        logger.info("--> shutting down all nodes except the one that holds the primary");
        internalCluster().stopRandomNode(InternalTestCluster.nameFilter(nodes.get(0)));
        internalCluster().stopRandomNode(InternalTestCluster.nameFilter(nodes.get(1)));
        ensureStableCluster(1);

        logger.info("--> setting allocation filtering to only allow allocation on the currently running node");
        client().admin().indices().prepareUpdateSettings("idx").setSettings(
            Settings.builder().put("index.routing.allocation.include._name", primaryNodeName)).get();

        logger.info("--> restarting the stopped nodes");
        internalCluster().startNode(Settings.builder().put("node.name", nodes.get(0)).build());
        internalCluster().startNode(Settings.builder().put("node.name", nodes.get(1)).build());
        ensureStableCluster(3);

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        assertBusy(() -> {
            if (includeDiskInfo) {
                // wait till all cluster info is ready
                assertEquals(3, client().admin().cluster().prepareAllocationExplain()
                    .setIndex("idx").setShard(0).setPrimary(true).setIncludeDiskInfo(true).get()
                    .getExplanation().getClusterInfo().getNodeLeastAvailableDiskUsages().size());
            }
        });
        ClusterAllocationExplanation explanation = runExplain(false, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertFalse(isPrimary);

        // verify current node info
        assertNotEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNull(currentNode);

        // verify unassigned info
        assertNotNull(unassignedInfo);
        assertEquals(Reason.NODE_LEFT, unassignedInfo.getReason());
        assertEquals(AllocationStatus.NO_ATTEMPT, unassignedInfo.getLastAllocationStatus());

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 3);

        // verify decision objects
        assertTrue(allocateDecision.isDecisionTaken());
        assertFalse(moveDecision.isDecisionTaken());
        AllocationDecision decisionToAllocate = allocateDecision.getAllocationDecision();
        assertTrue(decisionToAllocate == AllocationDecision.FETCH_PENDING || decisionToAllocate == AllocationDecision.NO);
        if (decisionToAllocate == AllocationDecision.FETCH_PENDING) {
            assertEquals("cannot allocate because information about existing shard data is still being retrieved from some of the nodes",
                allocateDecision.getExplanation());
        } else {
            assertEquals("cannot allocate because allocation is not permitted to any of the nodes", allocateDecision.getExplanation());
        }
        assertNull(allocateDecision.getAllocationId());
        assertNull(allocateDecision.getTargetNode());
        assertEquals(0L, allocateDecision.getConfiguredDelayInMillis());
        assertEquals(0L, allocateDecision.getRemainingDelayInMillis());
        assertEquals(3, allocateDecision.getNodeDecisions().size());
        for (NodeAllocationResult result : allocateDecision.getNodeDecisions()) {
            assertNotNull(result.getNode());
            boolean nodeHoldingPrimary = result.getNode().getName().equals(primaryNodeName);
            assertEquals(AllocationDecision.NO, result.getNodeDecision());
            if (includeYesDecisions) {
                assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(1));
            } else {
                assertEquals(1, result.getCanAllocateDecision().getDecisions().size());
            }
            for (Decision d : result.getCanAllocateDecision().getDecisions()) {
                if (d.label().equals("same_shard") && nodeHoldingPrimary) {
                    assertEquals(Decision.Type.NO, d.type());
                    assertThat(d.getExplanation(), startsWith(
                        "the shard cannot be allocated to the same node on which a copy of the shard already exists"));
                } else if (d.label().equals("filter") && nodeHoldingPrimary == false) {
                    assertEquals(Decision.Type.NO, d.type());
                    assertEquals("node does not match [index.routing.allocation.include] filters [_name:\"" + primaryNodeName + "\"]",
                        d.getExplanation());
                } else {
                    assertEquals(Decision.Type.YES, d.type());
                    assertNotNull(d.getExplanation());
                }
            }
        }
    }

    public void testAllocationFilteringOnIndexCreation() throws Exception {
        logger.info("--> starting 2 nodes");
        internalCluster().startNodes(2);
        ensureStableCluster(2);

        logger.info("--> creating an index with 1 primary, 0 replicas, with allocation filtering so the primary can't be assigned");
        createIndexAndIndexData(1, 0, Settings.builder().put("index.routing.allocation.include._name", "non_existent_node").build(), false);

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(true, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertTrue(isPrimary);

        // verify current node info
        assertNotEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNull(currentNode);

        // verify unassigned info
        assertNotNull(unassignedInfo);
        assertEquals(Reason.INDEX_CREATED, unassignedInfo.getReason());
        assertEquals(AllocationStatus.DECIDERS_NO, unassignedInfo.getLastAllocationStatus());

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 2);

        // verify decision objects
        assertTrue(allocateDecision.isDecisionTaken());
        assertFalse(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.NO, allocateDecision.getAllocationDecision());
        assertEquals("cannot allocate because allocation is not permitted to any of the nodes", allocateDecision.getExplanation());
        assertNull(allocateDecision.getAllocationId());
        assertNull(allocateDecision.getTargetNode());
        assertEquals(0L, allocateDecision.getConfiguredDelayInMillis());
        assertEquals(0L, allocateDecision.getRemainingDelayInMillis());
        assertEquals(2, allocateDecision.getNodeDecisions().size());
        for (NodeAllocationResult result : allocateDecision.getNodeDecisions()) {
            assertNotNull(result.getNode());
            assertEquals(AllocationDecision.NO, result.getNodeDecision());
            if (includeYesDecisions) {
                assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(1));
            } else {
                assertEquals(1, result.getCanAllocateDecision().getDecisions().size());
            }
            for (Decision d : result.getCanAllocateDecision().getDecisions()) {
                if (d.label().equals("filter")) {
                    assertEquals(Decision.Type.NO, d.type());
                    assertEquals("node does not match [index.routing.allocation.include] filters [_name:\"non_existent_node\"]",
                        d.getExplanation());
                }
            }
        }
    }

    public void testAllocationFilteringPreventsShardMove() throws Exception {
        logger.info("--> starting 2 nodes");
        internalCluster().startNodes(2);
        ensureStableCluster(2);

        logger.info("--> creating an index with 1 primary and 0 replicas");
        createIndexAndIndexData(1, 0);

        logger.info("--> setting up allocation filtering to prevent allocation to both nodes");
        client().admin().indices().prepareUpdateSettings("idx").setSettings(
            Settings.builder().put("index.routing.allocation.include._name", "non_existent_node")).get();

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(true, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertTrue(isPrimary);

        // verify current node info
        assertEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNotNull(currentNode);

        // verify unassigned info
        assertNull(unassignedInfo);

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 2);

        // verify decision object
        assertFalse(allocateDecision.isDecisionTaken());
        assertTrue(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.NO, moveDecision.getAllocationDecision());
        assertEquals("cannot move shard to another node, even though it is not allowed to remain on its current node",
            moveDecision.getExplanation());
        assertFalse(moveDecision.canRemain());
        assertFalse(moveDecision.forceMove());
        assertFalse(moveDecision.canRebalanceCluster());
        assertNull(moveDecision.getClusterRebalanceDecision());
        assertNull(moveDecision.getTargetNode());
        assertEquals(0, moveDecision.getCurrentNodeRanking());
        // verifying can remain decision object
        assertNotNull(moveDecision.getCanRemainDecision());
        assertEquals(Decision.Type.NO, moveDecision.getCanRemainDecision().type());
        for (Decision d : moveDecision.getCanRemainDecision().getDecisions()) {
            if (d.label().equals("filter")) {
                assertEquals(Decision.Type.NO, d.type());
                assertEquals("node does not match [index.routing.allocation.include] filters [_name:\"non_existent_node\"]",
                    d.getExplanation());
            } else {
                assertEquals(Decision.Type.YES, d.type());
                assertNotNull(d.getExplanation());
            }
        }
        // verify node decisions
        assertEquals(1, moveDecision.getNodeDecisions().size());
        NodeAllocationResult result = moveDecision.getNodeDecisions().get(0);
        assertNotNull(result.getNode());
        assertEquals(1, result.getWeightRanking());
        assertEquals(AllocationDecision.NO, result.getNodeDecision());
        if (includeYesDecisions) {
            assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(1));
        } else {
            assertEquals(1, result.getCanAllocateDecision().getDecisions().size());
        }
        for (Decision d : result.getCanAllocateDecision().getDecisions()) {
            if (d.label().equals("filter")) {
                assertEquals(Decision.Type.NO, d.type());
                assertEquals("node does not match [index.routing.allocation.include] filters [_name:\"non_existent_node\"]",
                    d.getExplanation());
            } else {
                assertEquals(Decision.Type.YES, d.type());
                assertNotNull(d.getExplanation());
            }
        }
    }

    public void testRebalancingNotAllowed() throws Exception {
        logger.info("--> starting a single node");
        internalCluster().startNode();

        logger.info("--> creating an index with 5 shards, all allocated to the single node");
        createIndexAndIndexData(5, 0);

        logger.info("--> disabling rebalancing on the index");
        client().admin().indices().prepareUpdateSettings("idx").setSettings(
            Settings.builder().put("index.routing.rebalance.enable", "none")).get();

        logger.info("--> starting another node, with rebalancing disabled, it should get no shards");
        internalCluster().startNode();

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(true, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertTrue(isPrimary);

        // verify current node info
        assertEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNotNull(currentNode);

        // verify unassigned info
        assertNull(unassignedInfo);

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 2);

        // verify decision object
        assertFalse(allocateDecision.isDecisionTaken());
        assertTrue(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.NO, moveDecision.getAllocationDecision());
        assertEquals("rebalancing is not allowed on the cluster even though there is at least one node on which the shard can be allocated",
            moveDecision.getExplanation());
        assertTrue(moveDecision.canRemain());
        assertFalse(moveDecision.forceMove());
        assertFalse(moveDecision.canRebalanceCluster());
        assertNotNull(moveDecision.getCanRemainDecision());
        assertNull(moveDecision.getTargetNode());
        assertEquals(2, moveDecision.getCurrentNodeRanking());
        // verifying cluster rebalance decision object
        assertNotNull(moveDecision.getClusterRebalanceDecision());
        assertEquals(Decision.Type.NO, moveDecision.getClusterRebalanceDecision().type());
        for (Decision d : moveDecision.getClusterRebalanceDecision().getDecisions()) {
            if (d.label().equals("enable")) {
                assertEquals(Decision.Type.NO, d.type());
                assertEquals("no rebalancing is allowed due to [index.routing.rebalance.enable=none]",
                    d.getExplanation());
            } else {
                assertEquals(Decision.Type.YES, d.type());
                assertNotNull(d.getExplanation());
            }
        }
        // verify node decisions
        assertEquals(1, moveDecision.getNodeDecisions().size());
        NodeAllocationResult result = moveDecision.getNodeDecisions().get(0);
        assertNotNull(result.getNode());
        assertEquals(1, result.getWeightRanking());
        assertEquals(AllocationDecision.YES, result.getNodeDecision());
        if (includeYesDecisions) {
            assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(0));
        } else {
            assertEquals(0, result.getCanAllocateDecision().getDecisions().size());
        }
        for (Decision d : result.getCanAllocateDecision().getDecisions()) {
            assertEquals(Decision.Type.YES, d.type());
            assertNotNull(d.getExplanation());
        }
    }

    public void testWorseBalance() throws Exception {
        logger.info("--> starting a single node");
        internalCluster().startNode();

        logger.info("--> creating an index with 5 shards, all allocated to the single node");
        createIndexAndIndexData(5, 0);

        logger.info("--> setting balancing threshold really high, so it won't be met");
        client().admin().cluster().prepareUpdateSettings().setTransientSettings(
            Settings.builder().put("cluster.routing.allocation.balance.threshold", 1000.0f)).get();

        logger.info("--> starting another node, with the rebalance threshold so high, it should not get any shards");
        internalCluster().startNode();

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(true, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertTrue(isPrimary);

        // verify current node info
        assertEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNotNull(currentNode);

        // verify unassigned info
        assertNull(unassignedInfo);

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 2);

        // verify decision object
        assertFalse(allocateDecision.isDecisionTaken());
        assertTrue(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.NO, moveDecision.getAllocationDecision());
        assertEquals("cannot rebalance as no target node exists that can both allocate this shard and improve the cluster balance",
            moveDecision.getExplanation());
        assertTrue(moveDecision.canRemain());
        assertFalse(moveDecision.forceMove());
        assertTrue(moveDecision.canRebalanceCluster());
        assertNotNull(moveDecision.getCanRemainDecision());
        assertNull(moveDecision.getTargetNode());
        assertEquals(1, moveDecision.getCurrentNodeRanking());
        // verifying cluster rebalance decision object
        assertNotNull(moveDecision.getClusterRebalanceDecision());
        assertEquals(Decision.Type.YES, moveDecision.getClusterRebalanceDecision().type());
        for (Decision d : moveDecision.getClusterRebalanceDecision().getDecisions()) {
            assertEquals(Decision.Type.YES, d.type());
            assertNotNull(d.getExplanation());
        }
        // verify node decisions
        assertEquals(1, moveDecision.getNodeDecisions().size());
        NodeAllocationResult result = moveDecision.getNodeDecisions().get(0);
        assertNotNull(result.getNode());
        assertEquals(1, result.getWeightRanking());
        assertEquals(AllocationDecision.WORSE_BALANCE, result.getNodeDecision());
        if (includeYesDecisions) {
            assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(0));
        } else {
            assertEquals(0, result.getCanAllocateDecision().getDecisions().size());
        }
        for (Decision d : result.getCanAllocateDecision().getDecisions()) {
            assertEquals(Decision.Type.YES, d.type());
            assertNotNull(d.getExplanation());
        }
    }

    public void testBetterBalanceButCannotAllocate() throws Exception {
        logger.info("--> starting a single node");
        String firstNode = internalCluster().startNode();

        logger.info("--> creating an index with 5 shards, all allocated to the single node");
        createIndexAndIndexData(5, 0);

        logger.info("--> setting up allocation filtering to only allow allocation to the current node");
        client().admin().indices().prepareUpdateSettings("idx").setSettings(
            Settings.builder().put("index.routing.allocation.include._name", firstNode)).get();

        logger.info("--> starting another node, with filtering not allowing allocation to the new node, it should not get any shards");
        internalCluster().startNode();

        boolean includeYesDecisions = randomBoolean();
        boolean includeDiskInfo = randomBoolean();
        ClusterAllocationExplanation explanation = runExplain(true, includeYesDecisions, includeDiskInfo);

        ShardId shardId = explanation.getShard();
        boolean isPrimary = explanation.isPrimary();
        ShardRoutingState shardRoutingState = explanation.getShardState();
        DiscoveryNode currentNode = explanation.getCurrentNode();
        UnassignedInfo unassignedInfo = explanation.getUnassignedInfo();
        ClusterInfo clusterInfo = explanation.getClusterInfo();
        AllocateUnassignedDecision allocateDecision = explanation.getShardAllocationDecision().getAllocateDecision();
        MoveDecision moveDecision = explanation.getShardAllocationDecision().getMoveDecision();

        // verify shard info
        assertEquals("idx", shardId.getIndexName());
        assertEquals(0, shardId.getId());
        assertTrue(isPrimary);

        // verify current node info
        assertEquals(ShardRoutingState.STARTED, shardRoutingState);
        assertNotNull(currentNode);

        // verify unassigned info
        assertNull(unassignedInfo);

        // verify cluster info
        verifyClusterInfo(clusterInfo, includeDiskInfo, 2);

        // verify decision object
        assertFalse(allocateDecision.isDecisionTaken());
        assertTrue(moveDecision.isDecisionTaken());
        assertEquals(AllocationDecision.NO, moveDecision.getAllocationDecision());
        assertEquals("cannot rebalance as no target node exists that can both allocate this shard and improve the cluster balance",
            moveDecision.getExplanation());
        assertTrue(moveDecision.canRemain());
        assertFalse(moveDecision.forceMove());
        assertTrue(moveDecision.canRebalanceCluster());
        assertNotNull(moveDecision.getCanRemainDecision());
        assertNull(moveDecision.getTargetNode());
        assertEquals(2, moveDecision.getCurrentNodeRanking());
        // verifying cluster rebalance decision object
        assertNotNull(moveDecision.getClusterRebalanceDecision());
        assertEquals(Decision.Type.YES, moveDecision.getClusterRebalanceDecision().type());
        for (Decision d : moveDecision.getClusterRebalanceDecision().getDecisions()) {
            assertEquals(Decision.Type.YES, d.type());
            assertNotNull(d.getExplanation());
        }
        // verify node decisions
        assertEquals(1, moveDecision.getNodeDecisions().size());
        NodeAllocationResult result = moveDecision.getNodeDecisions().get(0);
        assertNotNull(result.getNode());
        assertEquals(1, result.getWeightRanking());
        assertEquals(AllocationDecision.NO, result.getNodeDecision());
        if (includeYesDecisions) {
            assertThat(result.getCanAllocateDecision().getDecisions().size(), greaterThan(1));
        } else {
            assertEquals(1, result.getCanAllocateDecision().getDecisions().size());
        }
        String primaryNodeName = primaryNodeName();
        for (Decision d : result.getCanAllocateDecision().getDecisions()) {
            if (d.label().equals("filter")) {
                assertEquals(Decision.Type.NO, d.type());
                assertEquals("node does not match [index.routing.allocation.include] filters [_name:\"" + primaryNodeName + "\"]",
                    d.getExplanation());
            } else {
                assertEquals(Decision.Type.YES, d.type());
                assertNotNull(d.getExplanation());
            }
        }
    }

    private void verifyClusterInfo(ClusterInfo clusterInfo, boolean includeDiskInfo, int numNodes) {
        if (includeDiskInfo) {
            assertEquals(numNodes, clusterInfo.getNodeMostAvailableDiskUsages().size());
            assertEquals(numNodes, clusterInfo.getNodeLeastAvailableDiskUsages().size());
        } else {
            assertNull(clusterInfo);
        }
    }

    private ClusterAllocationExplanation runExplain(boolean primary, boolean includeYesDecisions, boolean includeDiskInfo)
        throws Exception {

        ClusterAllocationExplanation explanation = client().admin().cluster().prepareAllocationExplain()
            .setIndex("idx").setShard(0).setPrimary(primary)
            .setIncludeYesDecisions(includeYesDecisions)
            .setIncludeDiskInfo(includeDiskInfo)
            .get().getExplanation();
        if (logger.isDebugEnabled()) {
            XContentBuilder builder = JsonXContent.contentBuilder();
            builder.prettyPrint();
            builder.humanReadable(true);
            logger.debug("--> explain json output: \n{}", explanation.toXContent(builder, ToXContent.EMPTY_PARAMS).string());
        }
        return explanation;
    }

    private void createIndexAndIndexData(int numPrimaries, int numReplicas) {
        createIndexAndIndexData(numPrimaries, numReplicas, Settings.EMPTY, true);
    }

    private void createIndexAndIndexData(int numPrimaries, int numReplicas, Settings settings, boolean waitForShards) {
        client().admin().indices().prepareCreate("idx")
            .setSettings(Settings.builder()
                             .put("index.number_of_shards", numPrimaries)
                             .put("index.number_of_replicas", numReplicas)
                             .put(settings))
            .setWaitForActiveShards(waitForShards ? ActiveShardCount.ALL : ActiveShardCount.NONE)
            .get();
        if (waitForShards) {
            for (int i = 0; i < 10; i++) {
                index("idx", "t", Integer.toString(i), Collections.singletonMap("f1", Integer.toString(i)));
            }
            flushAndRefresh("idx");
        }
    }

    private String primaryNodeName() {
        ClusterState clusterState = client().admin().cluster().prepareState().get().getState();
        String nodeId = clusterState.getRoutingTable().index("idx").shard(0).primaryShard().currentNodeId();
        return clusterState.getRoutingNodes().node(nodeId).node().getName();
    }

    private String replicaNodeName() {
        ClusterState clusterState = client().admin().cluster().prepareState().get().getState();
        String nodeId = clusterState.getRoutingTable().index("idx").shard(0).replicaShards().get(0).currentNodeId();
        return clusterState.getRoutingNodes().node(nodeId).node().getName();
    }
}
