/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.snapshots;

import org.apache.logging.log4j.Level;
import org.elasticsearch.action.ActionFuture;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.snapshots.mockstore.MockRepository;
import org.elasticsearch.test.ClusterServiceUtils;
import org.elasticsearch.test.MockLog;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

public class SnapshotsServiceIT extends AbstractSnapshotIntegTestCase {

    public void testDeletingSnapshotsIsLoggedAfterClusterStateIsProcessed() throws Exception {
        createRepository("test-repo", "fs");
        createIndexWithRandomDocs("test-index", randomIntBetween(1, 42));
        createSnapshot("test-repo", "test-snapshot", List.of("test-index"));

        try (var mockLog = MockLog.capture(SnapshotsService.class)) {
            mockLog.addExpectation(
                new MockLog.UnseenEventExpectation(
                    "[does-not-exist]",
                    SnapshotsService.class.getName(),
                    Level.INFO,
                    "deleting snapshots [does-not-exist] from repository [test-repo]"
                )
            );

            mockLog.addExpectation(
                new MockLog.SeenEventExpectation(
                    "[deleting test-snapshot]",
                    SnapshotsService.class.getName(),
                    Level.INFO,
                    "deleting snapshots [test-snapshot] from repository [test-repo]"
                )
            );

            mockLog.addExpectation(
                new MockLog.SeenEventExpectation(
                    "[test-snapshot deleted]",
                    SnapshotsService.class.getName(),
                    Level.INFO,
                    "snapshots [test-snapshot/*] deleted"
                )
            );

            final SnapshotMissingException e = expectThrows(
                SnapshotMissingException.class,
                startDeleteSnapshot("test-repo", "does-not-exist")
            );
            assertThat(e.getMessage(), containsString("[test-repo:does-not-exist] is missing"));
            assertThat(startDeleteSnapshot("test-repo", "test-snapshot").actionGet().isAcknowledged(), is(true));

            awaitNoMoreRunningOperations(); // ensure background file deletion is completed
            mockLog.assertAllExpectationsMatched();
        } finally {
            deleteRepository("test-repo");
        }
    }

    public void testSnapshotDeletionFailureShouldBeLogged() throws Exception {
        createRepository("test-repo", "mock");
        createIndexWithRandomDocs("test-index", randomIntBetween(1, 42));
        createSnapshot("test-repo", "test-snapshot", List.of("test-index"));

        try (var mockLog = MockLog.capture(SnapshotsService.class)) {
            mockLog.addExpectation(
                new MockLog.SeenEventExpectation(
                    "[test-snapshot]",
                    SnapshotsService.class.getName(),
                    Level.WARN,
                    "failed to complete snapshot deletion for [test-snapshot] from repository [test-repo]"
                )
            );

            if (randomBoolean()) {
                // Failure when listing root blobs
                final MockRepository mockRepository = getRepositoryOnMaster("test-repo");
                mockRepository.setRandomControlIOExceptionRate(1.0);
                final Exception e = expectThrows(Exception.class, startDeleteSnapshot("test-repo", "test-snapshot"));
                assertThat(e.getCause().getMessage(), containsString("Random IOException"));
            } else {
                // Failure when finalizing on index-N file
                final ActionFuture<AcknowledgedResponse> deleteFuture;
                blockMasterFromFinalizingSnapshotOnIndexFile("test-repo");
                deleteFuture = startDeleteSnapshot("test-repo", "test-snapshot");
                waitForBlock(internalCluster().getMasterName(), "test-repo");
                unblockNode("test-repo", internalCluster().getMasterName());
                final Exception e = expectThrows(Exception.class, deleteFuture);
                assertThat(e.getCause().getMessage(), containsString("exception after block"));
            }

            mockLog.assertAllExpectationsMatched();
        } finally {
            deleteRepository("test-repo");
        }
    }

    public void testDeleteSnapshotWhenNotWaitingForCompletion() throws Exception {
        createIndexWithRandomDocs("test-index", randomIntBetween(1, 5));
        createRepository("test-repo", "mock");
        createSnapshot("test-repo", "test-snapshot", List.of("test-index"));
        MockRepository repository = getRepositoryOnMaster("test-repo");
        PlainActionFuture<AcknowledgedResponse> listener = new PlainActionFuture<>();
        repository.blockOnDataFiles();
        try {
            clusterAdmin().prepareDeleteSnapshot("test-repo", "test-snapshot").setWaitForCompletion(false).execute(listener);
            listener.get(5, TimeUnit.SECONDS);
            assertNotNull(getSnapshot("test-repo", "test-snapshot"));
        } finally {
            repository.unblock();
        }
        assertBusy(() -> assertThrows(SnapshotMissingException.class, () -> getSnapshot("test-repo", "test-snapshot")));
    }

    public void testDeleteSnapshotWhenWaitingForCompletion() throws Exception {
        createIndexWithRandomDocs("test-index", randomIntBetween(1, 5));
        createRepository("test-repo", "mock");
        createSnapshot("test-repo", "test-snapshot", List.of("test-index"));
        MockRepository repository = getRepositoryOnMaster("test-repo");
        PlainActionFuture<AcknowledgedResponse> listener = new PlainActionFuture<>();
        repository.blockOnDataFiles();
        try {
            clusterAdmin().prepareDeleteSnapshot("test-repo", "test-snapshot").setWaitForCompletion(true).execute(listener);
            // The listener won't be resolved, and snapshot won't be deleted until we remove the block
            assertFalse(listener.isDone());
            assertNotNull(getSnapshot("test-repo", "test-snapshot"));
        } finally {
            repository.unblock();
        }
        listener.get(5, TimeUnit.SECONDS);
        assertThrows(SnapshotMissingException.class, () -> getSnapshot("test-repo", "test-snapshot"));
    }

    public void testRerouteWhenShardSnapshotsCompleted() throws Exception {
        final var repoName = randomIdentifier();
        createRepository(repoName, "mock");
        internalCluster().ensureAtLeastNumDataNodes(1);
        final var originalNode = internalCluster().startDataOnlyNode();

        final var indexName = randomIdentifier();
        createIndexWithContent(
            indexName,
            indexSettings(1, 0).put(IndexMetadata.INDEX_ROUTING_REQUIRE_GROUP_PREFIX + "._name", originalNode).build()
        );

        final var snapshotFuture = startFullSnapshotBlockedOnDataNode(randomIdentifier(), repoName, originalNode);

        // Use allocation filtering to push the shard to a new node, but it will not do so yet because of the ongoing snapshot.
        updateIndexSettings(
            Settings.builder()
                .putNull(IndexMetadata.INDEX_ROUTING_REQUIRE_GROUP_PREFIX + "._name")
                .put(IndexMetadata.INDEX_ROUTING_EXCLUDE_GROUP_PREFIX + "._name", originalNode)
        );

        final var shardMovedListener = ClusterServiceUtils.addTemporaryStateListener(
            internalCluster().getCurrentMasterNodeInstance(ClusterService.class),
            state -> {
                final var primaryShard = state.routingTable().index(indexName).shard(0).primaryShard();
                return primaryShard.started() && originalNode.equals(state.nodes().get(primaryShard.currentNodeId()).getName()) == false;
            }
        );
        assertFalse(shardMovedListener.isDone());

        unblockAllDataNodes(repoName);
        assertEquals(SnapshotState.SUCCESS, snapshotFuture.get(10, TimeUnit.SECONDS).getSnapshotInfo().state());

        // Now that the snapshot completed the shard should move to its new location.
        safeAwait(shardMovedListener);
        ensureGreen(indexName);
    }
}
