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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.cluster.coordination.CoordinationMetaData.VotingConfiguration;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.threadpool.ThreadPool.Names;
import org.elasticsearch.transport.TransportService;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.elasticsearch.discovery.DiscoveryModule.DISCOVERY_HOSTS_PROVIDER_SETTING;
import static org.elasticsearch.discovery.zen.SettingsBasedHostsProvider.DISCOVERY_ZEN_PING_UNICAST_HOSTS_SETTING;

public class ClusterBootstrapService {

    public static final Setting<List<String>> INITIAL_MASTER_NODES_SETTING =
        Setting.listSetting("cluster.initial_master_nodes", Collections.emptyList(), Function.identity(), Property.NodeScope);

    public static final Setting<TimeValue> UNCONFIGURED_BOOTSTRAP_TIMEOUT_SETTING =
        Setting.timeSetting("discovery.unconfigured_bootstrap_timeout",
            TimeValue.timeValueSeconds(3), TimeValue.timeValueMillis(1), Property.NodeScope);

    private static final Logger logger = LogManager.getLogger(ClusterBootstrapService.class);
    private final List<String> initialMasterNodes;
    @Nullable // null if discoveryIsConfigured()
    private final TimeValue unconfiguredBootstrapTimeout;
    private final TransportService transportService;
    private final Supplier<Iterable<DiscoveryNode>> discoveredNodesSupplier;
    private final Consumer<VotingConfiguration> votingConfigurationConsumer;
    private final AtomicBoolean bootstrappingPermitted = new AtomicBoolean(true);

    public ClusterBootstrapService(Settings settings, TransportService transportService,
                                   Supplier<Iterable<DiscoveryNode>> discoveredNodesSupplier,
                                   Consumer<VotingConfiguration> votingConfigurationConsumer) {
        initialMasterNodes = INITIAL_MASTER_NODES_SETTING.get(settings);
        unconfiguredBootstrapTimeout = discoveryIsConfigured(settings) ? null : UNCONFIGURED_BOOTSTRAP_TIMEOUT_SETTING.get(settings);
        this.transportService = transportService;
        this.discoveredNodesSupplier = discoveredNodesSupplier;
        this.votingConfigurationConsumer = votingConfigurationConsumer;
    }

    public static boolean discoveryIsConfigured(Settings settings) {
        return Stream.of(DISCOVERY_HOSTS_PROVIDER_SETTING, DISCOVERY_ZEN_PING_UNICAST_HOSTS_SETTING, INITIAL_MASTER_NODES_SETTING)
            .anyMatch(s -> s.exists(settings));
    }

    void onFoundPeersUpdated() {
        final Set<DiscoveryNode> nodes = getDiscoveredNodes();
        if (transportService.getLocalNode().isMasterNode() && initialMasterNodes.isEmpty() == false
            && nodes.stream().noneMatch(Coordinator::isZen1Node) && checkWaitRequirements(nodes)) {

            startBootstrap(nodes);
        }
    }

    void scheduleUnconfiguredBootstrap() {
        if (unconfiguredBootstrapTimeout == null) {
            return;
        }

        if (transportService.getLocalNode().isMasterNode() == false) {
            return;
        }

        logger.info("no discovery configuration found, will perform best-effort cluster bootstrapping after [{}] " +
            "unless existing master is discovered", unconfiguredBootstrapTimeout);

        transportService.getThreadPool().scheduleUnlessShuttingDown(unconfiguredBootstrapTimeout, Names.GENERIC, new Runnable() {
            @Override
            public void run() {
                final Set<DiscoveryNode> discoveredNodes = getDiscoveredNodes();
                final List<DiscoveryNode> zen1Nodes = discoveredNodes.stream().filter(Coordinator::isZen1Node).collect(Collectors.toList());
                if (zen1Nodes.isEmpty()) {
                    logger.debug("performing best-effort cluster bootstrapping with {}", discoveredNodes);
                    startBootstrap(discoveredNodes);
                } else {
                    logger.info("avoiding best-effort cluster bootstrapping due to discovery of pre-7.0 nodes {}", zen1Nodes);
                }
            }

            @Override
            public String toString() {
                return "unconfigured-discovery delayed bootstrap";
            }
        });
    }

    private Set<DiscoveryNode> getDiscoveredNodes() {
        return Stream.concat(Stream.of(transportService.getLocalNode()),
            StreamSupport.stream(discoveredNodesSupplier.get().spliterator(), false)).collect(Collectors.toSet());
    }

    private void startBootstrap(Set<DiscoveryNode> discoveryNodes) {
        if (bootstrappingPermitted.compareAndSet(true, false)) {
            doBootstrap(new VotingConfiguration(discoveryNodes.stream().map(DiscoveryNode::getId).collect(Collectors.toSet())));
        }
    }

    private void doBootstrap(VotingConfiguration votingConfiguration) {
        assert transportService.getLocalNode().isMasterNode();

        try {
            votingConfigurationConsumer.accept(votingConfiguration);
        } catch (Exception e) {
            logger.warn(new ParameterizedMessage("exception when bootstrapping with {}, rescheduling", votingConfiguration), e);
            transportService.getThreadPool().scheduleUnlessShuttingDown(TimeValue.timeValueSeconds(10), Names.GENERIC,
                new Runnable() {
                    @Override
                    public void run() {
                        doBootstrap(votingConfiguration);
                    }

                    @Override
                    public String toString() {
                        return "retry of failed bootstrapping with " + votingConfiguration;
                    }
                }
            );
        }
    }

    private static boolean matchesRequirement(DiscoveryNode discoveryNode, String requirement) {
        return discoveryNode.getName().equals(requirement)
            || discoveryNode.getAddress().toString().equals(requirement)
            || discoveryNode.getAddress().getAddress().equals(requirement);
    }

    private boolean checkWaitRequirements(Set<DiscoveryNode> nodes) {
        final Set<DiscoveryNode> selectedNodes = new HashSet<>();
        for (final String requirement : initialMasterNodes) {
            final Set<DiscoveryNode> matchingNodes
                = nodes.stream().filter(n -> matchesRequirement(n, requirement)).collect(Collectors.toSet());

            if (matchingNodes.isEmpty()) {
                return false;
            }
            if (matchingNodes.size() > 1) {
                bootstrappingPermitted.set(false);
                logger.warn("bootstrapping cancelled: [{}] matches {}", requirement, matchingNodes);
                return false;
            }

            for (final DiscoveryNode matchingNode : matchingNodes) {
                if (selectedNodes.add(matchingNode) == false) {
                    bootstrappingPermitted.set(false);
                    logger.warn("bootstrapping cancelled: [{}] matches {}", matchingNode, initialMasterNodes.stream()
                        .filter(r -> matchesRequirement(matchingNode, requirement)).collect(Collectors.toList()));
                    return false;
                }
            }
        }

        return true;
    }
}
