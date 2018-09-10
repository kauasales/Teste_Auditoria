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

package org.elasticsearch.discovery.zen;

import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.test.ESIntegTestCase;
import org.junit.Before;

import java.util.function.Consumer;

import static org.elasticsearch.discovery.DiscoveryModule.DISCOVERY_HOSTS_PROVIDER_SETTING;
import static org.elasticsearch.discovery.zen.SettingsBasedHostsProvider.DISCOVERY_ZEN_PING_UNICAST_HOSTS_SETTING;
import static org.elasticsearch.discovery.zen.SettingsBasedHostsProvider.LIMIT_LOCAL_PORTS_COUNT;
import static org.elasticsearch.transport.TcpTransport.PORT;

@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0, numClientNodes = 0)
public class SettingsBasedHostProviderIT extends ESIntegTestCase {

    private Consumer<Builder> configureDiscovery;

    @Before
    public void setDefaultDiscoveryConfiguration() {
        configureDiscovery = b -> {
        };
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        Settings.Builder builder = Settings.builder().put(super.nodeSettings(nodeOrdinal));

        // super.nodeSettings enables file-based discovery, but here we disable it again so we can test the static list:
        if (randomBoolean()) {
            builder.putList(DISCOVERY_HOSTS_PROVIDER_SETTING.getKey());
        } else {
            builder.remove(DISCOVERY_HOSTS_PROVIDER_SETTING.getKey());
        }

        builder.remove(DISCOVERY_ZEN_PING_UNICAST_HOSTS_SETTING.getKey());

        configureDiscovery.accept(builder);
        return builder.build();
    }

    public void testClusterFormsWithSingleSeedHostInSettings() {
        final String seedNodeName = internalCluster().startNode();
        final NodesInfoResponse nodesInfoResponse
            = client(seedNodeName).admin().cluster().nodesInfo(new NodesInfoRequest("_local")).actionGet();
        final String seedNodeAddress = nodesInfoResponse.getNodes().get(0).getTransport().getAddress().publishAddress().toString();
        configureDiscovery = b -> b.putList(DISCOVERY_ZEN_PING_UNICAST_HOSTS_SETTING.getKey(), seedNodeAddress);
        logger.info("--> using seed node address {}", seedNodeAddress);

        int extraNodes = randomIntBetween(1, 5);
        internalCluster().startNodes(extraNodes);

        ensureStableCluster(extraNodes + 1);
    }

    public void testClusterFormsByScanningPorts() {
        final String seedNodeName = internalCluster().startNode();
        final NodesInfoResponse nodesInfoResponse
            = client(seedNodeName).admin().cluster().nodesInfo(new NodesInfoRequest("_local")).actionGet();
        final int seedNodePort = nodesInfoResponse.getNodes().get(0).getTransport().getAddress().publishAddress().getPort();
        final int minPort = randomIntBetween(seedNodePort - LIMIT_LOCAL_PORTS_COUNT + 1, seedNodePort - 1);
        final String portSpec = minPort + "-" + seedNodePort;

        logger.info("--> using port specification [{}]", portSpec);

        configureDiscovery = b -> b.put(PORT.getKey(), portSpec);

        internalCluster().startNode();
        ensureStableCluster(2);
    }
}
