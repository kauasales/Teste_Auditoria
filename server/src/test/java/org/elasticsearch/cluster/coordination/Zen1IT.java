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
package org.elasticsearch.cluster.coordination;

import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.routing.UnassignedInfo;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.InternalTestCluster;
import org.elasticsearch.test.discovery.TestZenDiscovery;
import org.elasticsearch.test.junit.annotations.TestLogging;

import java.util.List;
import java.util.stream.IntStream;

import static org.elasticsearch.node.Node.NODE_NAME_SETTING;
import static org.hamcrest.Matchers.equalTo;

@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0)
@TestLogging("org.elasticsearch.cluster.coordination:TRACE,org.elasticsearch.discovery.zen:TRACE")
public class Zen1IT extends ESIntegTestCase {

    private static Settings ZEN1_SETTINGS = Coordinator.addZen1Attribute(Settings.builder()
        .put(TestZenDiscovery.USE_ZEN2.getKey(), false)
        .put(TestZenDiscovery.USE_MOCK_PINGS.getKey(), false)) // Zen2 does not know about mock pings
        .build();

    private static Settings ZEN2_SETTINGS = Settings.builder()
        .put(TestZenDiscovery.USE_ZEN2.getKey(), true)
        .build();

    public void testZen2NodesJoiningZen1Cluster() {
        internalCluster().startNodes(randomIntBetween(1, 3), ZEN1_SETTINGS);
        internalCluster().startNodes(randomIntBetween(1, 3), ZEN2_SETTINGS);
        createIndex("test");
    }

    public void testZen1NodesJoiningZen2Cluster() {
        internalCluster().startNodes(randomIntBetween(1, 3), ZEN2_SETTINGS);
        internalCluster().startNodes(randomIntBetween(1, 3), ZEN1_SETTINGS);
        createIndex("test");
    }

    public void testMixedClusterFormation() throws Exception {
        final int zen1NodeCount = randomIntBetween(1, 3);
        final int zen2NodeCount = randomIntBetween(1, 3);
        logger.info("starting cluster of [{}] Zen1 nodes and [{}] Zen2 nodes", zen1NodeCount, zen2NodeCount);
        final List<String> nodes = internalCluster().startNodes(IntStream.range(0, zen1NodeCount + zen2NodeCount)
            .mapToObj(i -> i < zen1NodeCount ? ZEN1_SETTINGS : ZEN2_SETTINGS).toArray(Settings[]::new));

        for (final String node : nodes) {
            if (zen1NodeCount == 1 && node.equals(nodes.get(0))) {
                // Do not restart the only Zen1 node, because it cannot recover state from the Zen2 nodes. This is actually kinda bad,
                // if the Zen1 node restarts quickly enough then the Zen2 nodes will not bootstrap themselves and will try and join the
                // Zen1 node but they won't be able to because its cluster state version is 1.
                // TODO fix this
                continue;
            }

            internalCluster().restartNode(node, InternalTestCluster.EMPTY_CALLBACK);
            ensureStableCluster(zen1NodeCount + zen2NodeCount);
        }
    }

    private void testRollingUpgradeFromZen1ToZen2(final int nodeCount) throws Exception {
        final List<String> zen1Nodes = internalCluster().startNodes(nodeCount, ZEN1_SETTINGS);

        createIndex("test",
            Settings.builder()
                .put(UnassignedInfo.INDEX_DELAYED_NODE_LEFT_TIMEOUT_SETTING.getKey(), TimeValue.ZERO) // assign shards
                .put(IndexMetaData.SETTING_NUMBER_OF_SHARDS, nodeCount) // causes rebalancing
                .put(IndexMetaData.SETTING_NUMBER_OF_REPLICAS, 1)
                .build());
        ensureGreen("test");

        for (final String zen1Node : zen1Nodes) {
            logger.info("--> shutting down {}", zen1Node);
            internalCluster().stopRandomNode(s -> NODE_NAME_SETTING.get(s).equals(zen1Node));

            ensureStableCluster(nodeCount - 1);
            if (nodeCount > 2) {
                ensureGreen("test");
            } else {
                ensureYellow("test");
            }

            logger.info("--> starting replacement for {}", zen1Node);
            final String newNode = internalCluster().startNode(ZEN2_SETTINGS);
            ensureStableCluster(nodeCount);
            ensureGreen("test");
            logger.info("--> successfully replaced {} with {}", zen1Node, newNode);
        }

        assertThat(internalCluster().size(), equalTo(nodeCount));
    }

    public void testUpgradingFromZen1ToZen2ClusterWithTwoNodes() throws Exception {
        testRollingUpgradeFromZen1ToZen2(2);
    }

    public void testUpgradingFromZen1ToZen2ClusterWithThreeNodes() throws Exception {
        testRollingUpgradeFromZen1ToZen2(3);
    }

    public void testUpgradingFromZen1ToZen2ClusterWithFourNodes() throws Exception {
        testRollingUpgradeFromZen1ToZen2(4);
    }

    public void testUpgradingFromZen1ToZen2ClusterWithFiveNodes() throws Exception {
        testRollingUpgradeFromZen1ToZen2(5);
    }
}
