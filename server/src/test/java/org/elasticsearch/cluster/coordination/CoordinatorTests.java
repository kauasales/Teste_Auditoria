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

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterState.VotingConfiguration;
import org.elasticsearch.cluster.ESAllocationTestCase;
import org.elasticsearch.cluster.coordination.CoordinationState.PersistedState;
import org.elasticsearch.cluster.coordination.CoordinationStateTests.InMemoryPersistedState;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.node.DiscoveryNode.Role;
import org.elasticsearch.cluster.service.MasterService;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.component.AbstractComponent;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.discovery.PeerFinder.TransportAddressConnector;
import org.elasticsearch.discovery.zen.UnicastHostsProvider.HostsResolver;
import org.elasticsearch.indices.cluster.FakeThreadPoolMasterService;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.test.transport.CapturingTransport;
import org.elasticsearch.transport.RequestHandlerRegistry;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseOptions;
import org.elasticsearch.transport.TransportService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static java.util.Collections.emptySet;
import static java.util.Collections.unmodifiableList;
import static org.elasticsearch.cluster.coordination.CoordinationStateTests.clusterState;
import static org.elasticsearch.node.Node.NODE_NAME_SETTING;
import static org.elasticsearch.transport.TransportService.NOOP_TRANSPORT_INTERCEPTOR;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

@TestLogging("org.elasticsearch.cluster.coordination:TRACE,org.elasticsearch.cluster.discovery:TRACE")
public class CoordinatorTests extends ESTestCase {

    public void testCanStabilise() {
        final Cluster cluster = new Cluster(randomIntBetween(1, 5));
        cluster.stabilise();
    }

    private static String nodeIdFromIndex(int nodeIndex) {
        return "node" + nodeIndex;
    }

    class Cluster {

        static final long DEFAULT_STABILISATION_TIME = 3000L;

        final List<ClusterNode> clusterNodes;
        final DeterministicTaskQueue deterministicTaskQueue = new DeterministicTaskQueue(
            Settings.builder().put(NODE_NAME_SETTING.getKey(), "deterministic-task-queue").build());
        private final VotingConfiguration initialConfiguration;

        Cluster(int initialNodeCount) {
            logger.info("--> creating cluster of {} nodes", initialNodeCount);

            Set<String> initialNodeIds = new HashSet<>(initialNodeCount);
            for (int i = 0; i < initialNodeCount; i++) {
                initialNodeIds.add(nodeIdFromIndex(i));
            }
            initialConfiguration = new VotingConfiguration(initialNodeIds);

            clusterNodes = new ArrayList<>(initialNodeCount);
            for (int i = 0; i < initialNodeCount; i++) {
                final ClusterNode clusterNode = new ClusterNode(i);
                clusterNodes.add(clusterNode);
            }
        }

        void stabilise() {
            final long stabilisationStartTime = deterministicTaskQueue.getCurrentTimeMillis();
            while (deterministicTaskQueue.getCurrentTimeMillis() < stabilisationStartTime + DEFAULT_STABILISATION_TIME) {
                deterministicTaskQueue.runAllRunnableTasks(random());

                if (deterministicTaskQueue.hasDeferredTasks() == false) {
                    break; // TODO when fault detection is enabled this should be removed, as there should _always_ be deferred tasks
                }

                deterministicTaskQueue.advanceTime();
            }

            assertUniqueLeaderAndExpectedModes();
        }

        private void assertUniqueLeaderAndExpectedModes() {
            final ClusterNode leader = getAnyLeader();
            final long leaderTerm = leader.coordinator.getCurrentTerm();

            for (final ClusterNode clusterNode : clusterNodes) {
                if (clusterNode == leader) {
                    continue;
                }

                final String nodeId = clusterNode.getId();
                assertThat(nodeId + " has the same term as the leader", clusterNode.coordinator.getCurrentTerm(), is(leaderTerm));
                assertTrue("leader should have received a vote from " + nodeId,
                    leader.coordinator.hasJoinVoteFrom(clusterNode.getLocalNode()));
            }
        }

        ClusterNode getAnyLeader() {
            List<ClusterNode> allLeaders = clusterNodes.stream().filter(ClusterNode::isLeader).collect(Collectors.toList());
            assertThat(allLeaders, not(empty()));
            return randomFrom(allLeaders);
        }

        class ClusterNode extends AbstractComponent {
            private final int nodeIndex;
            private Coordinator coordinator;
            private DiscoveryNode localNode;
            private final PersistedState persistedState;
            private MasterService masterService;
            private TransportService transportService;
            private CapturingTransport capturingTransport;

            ClusterNode(int nodeIndex) {
                super(Settings.builder().put(NODE_NAME_SETTING.getKey(), nodeIdFromIndex(nodeIndex)).build());
                this.nodeIndex = nodeIndex;
                localNode = createDiscoveryNode();
                persistedState = new InMemoryPersistedState(1L,
                    clusterState(1L, 1L, localNode, initialConfiguration, initialConfiguration, 0L));
                setUp();
            }

            private DiscoveryNode createDiscoveryNode() {
                final TransportAddress transportAddress = buildNewFakeTransportAddress();
                // Generate the ephemeral ID deterministically, for repeatable tests. This means we have to pass everything else into the
                // constructor explicitly too.
                return new DiscoveryNode("", "node" + nodeIndex, UUIDs.randomBase64UUID(random()),
                    transportAddress.address().getHostString(),
                    transportAddress.getAddress(), transportAddress, Collections.emptyMap(),
                    EnumSet.allOf(Role.class), Version.CURRENT);
            }

            private void setUp() {

                capturingTransport = new CapturingTransport() {
                    @Override
                    protected void onSendRequest(long requestId, String action, TransportRequest request, DiscoveryNode destination) {
                        assert destination.equals(localNode) == false : "non-local message from " + localNode + " to itself";
                        super.onSendRequest(requestId, action, request, destination);

                        deterministicTaskQueue.scheduleNow(() ->
                            clusterNodes.stream().filter(d -> d.getLocalNode().equals(destination)).findAny().ifPresent(
                                destinationNode -> {

                                    final RequestHandlerRegistry requestHandler
                                        = destinationNode.capturingTransport.getRequestHandler(action);

                                    final TransportChannel transportChannel = new TransportChannel() {
                                        @Override
                                        public String getProfileName() {
                                            return "default";
                                        }

                                        @Override
                                        public String getChannelType() {
                                            return "coordinator-test-channel";
                                        }

                                        @Override
                                        public void sendResponse(final TransportResponse response) {
                                            deterministicTaskQueue.scheduleNow(() -> handleResponse(requestId, response));
                                        }

                                        @Override
                                        public void sendResponse(TransportResponse response, TransportResponseOptions options) {
                                            sendResponse(response);
                                        }

                                        @Override
                                        public void sendResponse(Exception exception) {
                                            deterministicTaskQueue.scheduleNow(() -> handleRemoteError(requestId, exception));
                                        }
                                    };

                                    try {
                                        requestHandler.processMessageReceived(request, transportChannel);
                                    } catch (Exception e) {
                                        deterministicTaskQueue.scheduleNow(() -> handleRemoteError(requestId, e));
                                    }
                                }
                            ));
                    }
                };

                masterService = new FakeThreadPoolMasterService("test", deterministicTaskQueue::scheduleNow);
                AtomicReference<ClusterState> currentState = new AtomicReference<>(getPersistedState().getLastAcceptedState());
                masterService.setClusterStateSupplier(currentState::get);
                masterService.setClusterStatePublisher((event, publishListener, ackListener) -> {
                    currentState.set(event.state());
                    publishListener.onResponse(null);
                });
                masterService.start();

                transportService = capturingTransport.createCapturingTransportService(
                    settings, deterministicTaskQueue.getThreadPool(), NOOP_TRANSPORT_INTERCEPTOR, a -> localNode, null, emptySet());
                transportService.start();
                transportService.acceptIncomingRequests();

                coordinator = new Coordinator(settings, transportService, ESAllocationTestCase.createAllocationService(Settings.EMPTY),
                    masterService, this::getPersistedState, Cluster.this::provideUnicastHosts) {

                    @Override
                    protected TransportAddressConnector getTransportAddressConnector() {
                        return (transportAddress, listener) -> {
                            for (final ClusterNode clusterNode : clusterNodes) {
                                if (clusterNode.getLocalNode().getAddress().equals(transportAddress)) {
                                    deterministicTaskQueue.scheduleNow(() -> listener.onResponse(clusterNode.getLocalNode()));
                                    break;
                                }
                            }
                            deterministicTaskQueue.scheduleNow(() ->
                                listener.onFailure(new ElasticsearchException("no such node: " + transportAddress + " in " + clusterNodes)));
                        };
                    }
                };

                coordinator.start();
                coordinator.startInitialJoin();
            }

            private PersistedState getPersistedState() {
                return persistedState;
            }

            String getId() {
                return localNode.getId();
            }

            public DiscoveryNode getLocalNode() {
                return localNode;
            }

            boolean isLeader() {
                return coordinator.getMode() == Coordinator.Mode.LEADER;
            }
        }

        private List<TransportAddress> provideUnicastHosts(HostsResolver hostsResolver) {
            final List<TransportAddress> unicastHosts = new ArrayList<>(clusterNodes.size());
            clusterNodes.forEach(n -> unicastHosts.add(n.getLocalNode().getAddress()));
            return unmodifiableList(unicastHosts);
        }
    }
}
