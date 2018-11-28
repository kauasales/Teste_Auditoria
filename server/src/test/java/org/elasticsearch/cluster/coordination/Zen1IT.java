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

import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequestBuilder;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.routing.UnassignedInfo;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.InternalTestCluster.RestartCallback;
import org.elasticsearch.test.discovery.TestZenDiscovery;
import org.elasticsearch.test.junit.annotations.TestLogging;

import java.util.List;
import java.util.stream.IntStream;

import static org.elasticsearch.node.Node.NODE_NAME_SETTING;
import static org.hamcrest.Matchers.equalTo;

@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0)
@TestLogging("org.elasticsearch.cluster.coordination:TRACE,org.elasticsearch.discovery.zen:TRACE")
public class Zen1IT extends ESIntegTestCase {

    private static Settings ZEN1_SETTINGS = Coordinator.addZen1Attribute(true, Settings.builder()
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
                // Restarting the only Zen1 node allows the Zen2 nodes to bootstrap, which prevents the Zen1 node from rejoining the
                // cluster, which is tested as part of the rolling upgrade tests, so don't do it here.
                continue;
            }
            internalCluster().restartNode(node, new RestartCallback() {
                @Override
                public Settings onNodeStopped(String restartingNode) {
                    String viaNode = randomValueOtherThan(restartingNode, () -> randomFrom(nodes));
                    final ClusterHealthRequestBuilder clusterHealthRequestBuilder = client(viaNode).admin().cluster().prepareHealth()
                        .setWaitForEvents(Priority.LANGUID)
                        .setWaitForNodes(Integer.toString(zen1NodeCount + zen2NodeCount - 1))
                        .setTimeout(TimeValue.timeValueSeconds(30));
                    ClusterHealthResponse clusterHealthResponse = clusterHealthRequestBuilder.get();
                    assertFalse(restartingNode, clusterHealthResponse.isTimedOut());
                    return Settings.EMPTY;
                }
            });
            ensureStableCluster(zen1NodeCount + zen2NodeCount);
        }
    }

    private void testRollingMigrationFromZen1ToZen2(final int nodeCount) throws Exception {
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

    public void testMigratingFromZen1ToZen2ClusterWithTwoNodes() throws Exception {
        testRollingMigrationFromZen1ToZen2(2);
    }

    public void testMigratingFromZen1ToZen2ClusterWithThreeNodes() throws Exception {
        testRollingMigrationFromZen1ToZen2(3);
    }

    public void testMigratingFromZen1ToZen2ClusterWithFourNodes() throws Exception {
        testRollingMigrationFromZen1ToZen2(4);
    }

    public void testMigratingFromZen1ToZen2ClusterWithFiveNodes() throws Exception {
        testRollingMigrationFromZen1ToZen2(5);
    }

    private void testRollingUpgradeFromZen1ToZen2(final int nodeCount) throws Exception {
        final List<String> nodes = internalCluster().startNodes(nodeCount, ZEN1_SETTINGS);

        createIndex("test",
            Settings.builder()
                .put(UnassignedInfo.INDEX_DELAYED_NODE_LEFT_TIMEOUT_SETTING.getKey(), TimeValue.ZERO) // assign shards
                .put(IndexMetaData.SETTING_NUMBER_OF_SHARDS, nodeCount) // causes rebalancing
                .put(IndexMetaData.SETTING_NUMBER_OF_REPLICAS, 1)
                .build());
        ensureGreen("test");

        internalCluster().rollingRestart(new RestartCallback() {
            @Override
            public void doAfterNodes(int n, Client client) {
                ensureGreen("test");
            }

            @Override
            public Settings onNodeStopped(String nodeName) {
                String viaNode = randomValueOtherThan(nodeName, () -> randomFrom(nodes));
                final ClusterHealthRequestBuilder clusterHealthRequestBuilder = client(viaNode).admin().cluster().prepareHealth()
                    .setWaitForEvents(Priority.LANGUID)
                    .setWaitForNodes(Integer.toString(nodeCount - 1))
                    .setTimeout(TimeValue.timeValueSeconds(30));
                if (nodeCount == 2) {
                    clusterHealthRequestBuilder.setWaitForYellowStatus();
                } else {
                    clusterHealthRequestBuilder.setWaitForGreenStatus();
                }
                ClusterHealthResponse clusterHealthResponse = clusterHealthRequestBuilder.get();
                assertFalse(nodeName, clusterHealthResponse.isTimedOut());
                return Coordinator.addZen1Attribute(false, Settings.builder().put(ZEN2_SETTINGS)).build();
            }
        });

        ensureStableCluster(nodeCount);
        ensureGreen("test");
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
