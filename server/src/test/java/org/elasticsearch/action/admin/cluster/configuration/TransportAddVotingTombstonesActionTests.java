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
package org.elasticsearch.action.admin.cluster.configuration;

import org.apache.lucene.util.SetOnce;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterState.VotingConfiguration;
import org.elasticsearch.cluster.ClusterStateObserver;
import org.elasticsearch.cluster.ClusterStateObserver.Listener;
import org.elasticsearch.cluster.ClusterStateUpdateTask;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.node.DiscoveryNode.Role;
import org.elasticsearch.cluster.node.DiscoveryNodes.Builder;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.transport.MockTransport;
import org.elasticsearch.threadpool.TestThreadPool;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.threadpool.ThreadPool.Names;
import org.elasticsearch.transport.TransportException;
import org.elasticsearch.transport.TransportResponseHandler;
import org.elasticsearch.transport.TransportService;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static org.elasticsearch.action.admin.cluster.configuration.TransportAddVotingTombstonesAction.MAXIMUM_VOTING_TOMBSTONES_SETTING;
import static org.elasticsearch.action.support.ActionFilters.EMPTY_FILTERS;
import static org.elasticsearch.cluster.ClusterState.builder;
import static org.elasticsearch.test.ClusterServiceUtils.createClusterService;
import static org.elasticsearch.test.ClusterServiceUtils.setState;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.sameInstance;
import static org.hamcrest.Matchers.startsWith;

public class TransportAddVotingTombstonesActionTests extends ESTestCase {

    private static ThreadPool threadPool;
    private static ClusterService clusterService;
    private static DiscoveryNode localNode, otherNode1, otherNode2, otherDataNode;

    private TransportService transportService;
    private ClusterStateObserver clusterStateObserver;

    @BeforeClass
    public static void createThreadPoolAndClusterService() {
        threadPool = new TestThreadPool("test", Settings.EMPTY);
        localNode = makeDiscoveryNode("local");
        otherNode1 = makeDiscoveryNode("other1");
        otherNode2 = makeDiscoveryNode("other2");
        otherDataNode = new DiscoveryNode("data", "data", buildNewFakeTransportAddress(), emptyMap(), emptySet(), Version.CURRENT);
        clusterService = createClusterService(threadPool, localNode);
    }

    private static DiscoveryNode makeDiscoveryNode(String name) {
        return new DiscoveryNode(name, name, buildNewFakeTransportAddress(), emptyMap(), singleton(Role.MASTER), Version.CURRENT);
    }

    @AfterClass
    public static void shutdownThreadPoolAndClusterService() {
        clusterService.stop();
        threadPool.shutdown();
    }

    @Before
    public void setupForTest() {
        final MockTransport transport = new MockTransport();
        transportService = transport.createTransportService(Settings.EMPTY, threadPool,
            TransportService.NOOP_TRANSPORT_INTERCEPTOR, boundTransportAddress -> localNode, null, emptySet());

        new TransportAddVotingTombstonesAction(transportService, clusterService, threadPool, EMPTY_FILTERS,
            new IndexNameExpressionResolver()); // registers action

        transportService.start();
        transportService.acceptIncomingRequests();

        final VotingConfiguration allNodesConfig = VotingConfiguration.of(localNode, otherNode1, otherNode2);

        setState(clusterService, builder(new ClusterName("cluster"))
            .nodes(new Builder().add(localNode).add(otherNode1).add(otherNode2).add(otherDataNode)
                .localNodeId(localNode.getId()).masterNodeId(localNode.getId()))
            .lastAcceptedConfiguration(allNodesConfig).lastCommittedConfiguration(allNodesConfig));

        clusterStateObserver = new ClusterStateObserver(clusterService, null, logger, threadPool.getThreadContext());
    }

    public void testWithdrawsVoteFromANode() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<AddVotingTombstonesResponse> responseHolder = new SetOnce<>();

        clusterStateObserver.waitForNextChange(new AdjustConfigurationForTombstones());
        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"other1"}),
            expectSuccess(r -> {
                responseHolder.set(r);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        assertThat(responseHolder.get().getCurrentTombstones(), contains(otherNode1));
        assertThat(clusterService.getClusterApplierService().state().getVotingTombstones(), contains(otherNode1));
    }

    public void testWithdrawsVotesFromMultipleNodes() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<AddVotingTombstonesResponse> responseHolder = new SetOnce<>();

        clusterStateObserver.waitForNextChange(new AdjustConfigurationForTombstones());
        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"other1", "other2"}),
            expectSuccess(r -> {
                responseHolder.set(r);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        assertThat(responseHolder.get().getCurrentTombstones(), containsInAnyOrder(otherNode1, otherNode2));
        assertThat(clusterService.getClusterApplierService().state().getVotingTombstones(), containsInAnyOrder(otherNode1, otherNode2));
    }

    public void testWithdrawsVotesFromNodesMatchingWildcard() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<AddVotingTombstonesResponse> responseHolder = new SetOnce<>();

        clusterStateObserver.waitForNextChange(new AdjustConfigurationForTombstones());
        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"other*"}),
            expectSuccess(r -> {
                responseHolder.set(r);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        assertThat(responseHolder.get().getCurrentTombstones(), containsInAnyOrder(otherNode1, otherNode2));
        assertThat(clusterService.getClusterApplierService().state().getVotingTombstones(), containsInAnyOrder(otherNode1, otherNode2));
    }

    public void testWithdrawsVotesFromAllMasterEligibleNodes() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<AddVotingTombstonesResponse> responseHolder = new SetOnce<>();

        clusterStateObserver.waitForNextChange(new AdjustConfigurationForTombstones());
        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"_all"}),
            expectSuccess(r -> {
                responseHolder.set(r);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        assertThat(responseHolder.get().getCurrentTombstones(), containsInAnyOrder(localNode, otherNode1, otherNode2));
        assertThat(clusterService.getClusterApplierService().state().getVotingTombstones(),
            containsInAnyOrder(localNode, otherNode1, otherNode2));
    }

    public void testWithdrawsVoteFromLocalNode() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<AddVotingTombstonesResponse> responseHolder = new SetOnce<>();

        clusterStateObserver.waitForNextChange(new AdjustConfigurationForTombstones());
        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"_local"}),
            expectSuccess(r -> {
                responseHolder.set(r);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        assertThat(responseHolder.get().getCurrentTombstones(), contains(localNode));
        assertThat(clusterService.getClusterApplierService().state().getVotingTombstones(), contains(localNode));
    }

    public void testReturnsImmediatelyIfVoteAlreadyWithdrawn() throws InterruptedException {
        setState(clusterService, builder(clusterService.state())
            .lastCommittedConfiguration(VotingConfiguration.of(localNode, otherNode2))
            .lastAcceptedConfiguration(VotingConfiguration.of(localNode, otherNode2)));

        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<AddVotingTombstonesResponse> responseHolder = new SetOnce<>();

        // no observer to reconfigure
        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"other1"}, TimeValue.ZERO),
            expectSuccess(r -> {
                responseHolder.set(r);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        assertThat(responseHolder.get().getCurrentTombstones(), contains(otherNode1));
        assertThat(clusterService.getClusterApplierService().state().getVotingTombstones(), contains(otherNode1));
    }

    public void testReturnsErrorIfNoMatchingNodes() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<TransportException> exceptionHolder = new SetOnce<>();

        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"not-a-node"}),
            expectError(e -> {
                exceptionHolder.set(e);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        final Throwable rootCause = exceptionHolder.get().getRootCause();
        assertThat(rootCause, instanceOf(IllegalArgumentException.class));
        assertThat(rootCause.getMessage(), equalTo("add voting tombstones request for [not-a-node] matched no master-eligible nodes"));
    }

    public void testOnlyMatchesMasterEligibleNodes() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<TransportException> exceptionHolder = new SetOnce<>();

        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"_all", "master:false"}),
            expectError(e -> {
                exceptionHolder.set(e);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        final Throwable rootCause = exceptionHolder.get().getRootCause();
        assertThat(rootCause, instanceOf(IllegalArgumentException.class));
        assertThat(rootCause.getMessage(),
            equalTo("add voting tombstones request for [_all, master:false] matched no master-eligible nodes"));
    }

    public void testReturnsErrorIfNoTombstonesAdded() throws InterruptedException {
        final ClusterState.Builder builder = builder(clusterService.state());
        builder.addVotingTombstone(otherNode1);
        setState(clusterService, builder);

        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<TransportException> exceptionHolder = new SetOnce<>();

        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"other1"}),
            expectError(e -> {
                exceptionHolder.set(e);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        final Throwable rootCause = exceptionHolder.get().getRootCause();
        assertThat(rootCause, instanceOf(IllegalArgumentException.class));
        assertThat(rootCause.getMessage(),
            equalTo("add voting tombstones request for [other1] matched no master-eligible nodes that do not already have tombstones"));
    }

    public void testReturnsErrorIfMaximumTombstoneCountExceeded() throws InterruptedException {
        final ClusterState.Builder builder = builder(clusterService.state())
            .metaData(MetaData.builder(clusterService.state().metaData()).persistentSettings(
                Settings.builder().put(clusterService.state().metaData().persistentSettings())
                    .put(MAXIMUM_VOTING_TOMBSTONES_SETTING.getKey(), 2).build()));
        builder.addVotingTombstone(localNode);
        final int existingCount, newCount;
        if (randomBoolean()) {
            builder.addVotingTombstone(otherNode1);
            existingCount = 2;
            newCount = 1;
        } else {
            existingCount = 1;
            newCount = 2;
        }
        setState(clusterService, builder);

        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<TransportException> exceptionHolder = new SetOnce<>();

        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"other*"}),
            expectError(e -> {
                exceptionHolder.set(e);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        final Throwable rootCause = exceptionHolder.get().getRootCause();
        assertThat(rootCause, instanceOf(IllegalArgumentException.class));
        assertThat(rootCause.getMessage(), equalTo("add voting tombstones request for [other*] would add [" + newCount +
            "] voting tombstones to the existing [" + existingCount +
            "] which would exceed the maximum of [2] set by [cluster.max_voting_tombstones]"));
    }

    public void testTimesOut() throws InterruptedException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        final SetOnce<TransportException> exceptionHolder = new SetOnce<>();

        transportService.sendRequest(localNode, AddVotingTombstonesAction.NAME,
            new AddVotingTombstonesRequest(new String[]{"other1"}, TimeValue.timeValueMillis(100)),
            expectError(e -> {
                exceptionHolder.set(e);
                countDownLatch.countDown();
            })
        );

        assertTrue(countDownLatch.await(30, TimeUnit.SECONDS));
        final Throwable rootCause = exceptionHolder.get().getRootCause();
        assertThat(rootCause,instanceOf(ElasticsearchTimeoutException.class));
        assertThat(rootCause.getMessage(), startsWith("timed out waiting for withdrawal of votes from [{other1}"));
    }

    private TransportResponseHandler<AddVotingTombstonesResponse> expectSuccess(Consumer<AddVotingTombstonesResponse> onResponse) {
        return responseHandler(onResponse, e -> {
            throw new AssertionError("unexpected", e);
        });
    }

    private TransportResponseHandler<AddVotingTombstonesResponse> expectError(Consumer<TransportException> onException) {
        return responseHandler(r -> {
            assert false : r;
        }, onException);
    }

    private TransportResponseHandler<AddVotingTombstonesResponse> responseHandler(Consumer<AddVotingTombstonesResponse> onResponse,
                                                                                  Consumer<TransportException> onException) {
        return new TransportResponseHandler<AddVotingTombstonesResponse>() {
            @Override
            public void handleResponse(AddVotingTombstonesResponse response) {
                onResponse.accept(response);
            }

            @Override
            public void handleException(TransportException exp) {
                onException.accept(exp);
            }

            @Override
            public String executor() {
                return Names.SAME;
            }

            @Override
            public AddVotingTombstonesResponse read(StreamInput in) throws IOException {
                return new AddVotingTombstonesResponse(in);
            }
        };
    }

    private class AdjustConfigurationForTombstones implements Listener {
        @Override
        public void onNewClusterState(ClusterState state) {
            clusterService.getMasterService().submitStateUpdateTask("reconfiguration", new ClusterStateUpdateTask() {
                @Override
                public ClusterState execute(ClusterState currentState) {
                    assertThat(currentState, sameInstance(state));
                    final Set<String> votingNodeIds = new HashSet<>();
                    currentState.nodes().forEach(n -> votingNodeIds.add(n.getId()));
                    currentState.getVotingTombstones().forEach(t -> votingNodeIds.remove(t.getId()));
                    final VotingConfiguration votingConfiguration = new VotingConfiguration(votingNodeIds);
                    return builder(currentState)
                        .lastAcceptedConfiguration(votingConfiguration)
                        .lastCommittedConfiguration(votingConfiguration).build();
                }

                @Override
                public void onFailure(String source, Exception e) {
                    throw new AssertionError("unexpected failure", e);
                }
            });
        }

        @Override
        public void onClusterServiceClose() {
            throw new AssertionError("unexpected close");
        }

        @Override
        public void onTimeout(TimeValue timeout) {
            throw new AssertionError("unexpected timeout");
        }
    }
}
