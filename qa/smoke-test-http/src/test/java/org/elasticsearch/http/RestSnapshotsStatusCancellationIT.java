/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.http;

import org.apache.http.client.methods.HttpGet;
import org.elasticsearch.action.admin.cluster.snapshots.status.SnapshotsStatusAction;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.client.Cancellable;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.CollectionUtils;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.snapshots.AbstractSnapshotIntegTestCase;
import org.elasticsearch.snapshots.SnapshotState;
import org.elasticsearch.snapshots.mockstore.MockRepository;
import org.elasticsearch.test.ESIntegTestCase;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.test.TaskAssertions.assertAllCancellableTasksAreCancelled;
import static org.elasticsearch.test.TaskAssertions.assertAllTasksHaveFinished;
import static org.elasticsearch.test.TaskAssertions.awaitTaskWithPrefix;
import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertAcked;

@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0, numClientNodes = 0)
public class RestSnapshotsStatusCancellationIT extends HttpSmokeTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return CollectionUtils.appendToCopy(super.nodePlugins(), MockRepository.Plugin.class);
    }

    public void testSnapshotStatusCancellation() throws Exception {
        internalCluster().startMasterOnlyNode();
        internalCluster().startDataOnlyNode();
        ensureStableCluster(2);

        createIndex("test-idx");
        final String repoName = "test-repo";
        assertAcked(
                client().admin().cluster().preparePutRepository(repoName)
                        .setType("mock").setSettings(Settings.builder().put("location", randomRepoPath())));

        final int snapshotCount = randomIntBetween(1, 5);
        final Collection<String> snapshotNames = new ArrayList<>();
        for (int i = 0; i < snapshotCount; i++) {
            final String snapshotName = "snapshot-" + i;
            snapshotNames.add(snapshotName);
            assertEquals(
                    SnapshotState.SUCCESS,
                    client().admin().cluster().prepareCreateSnapshot(repoName, "snapshot-" + i).setWaitForCompletion(true)
                            .get().getSnapshotInfo().state()
            );
        }

        final MockRepository repository = AbstractSnapshotIntegTestCase.getRepositoryOnMaster(repoName);
        repository.setBlockOnAnyFiles();

        final Request request = new Request(
            HttpGet.METHOD_NAME,
            "/_snapshot/" + repoName + "/"
                + String.join(",", randomSubsetOf(randomIntBetween(1, snapshotCount), snapshotNames))
                + "/_status"
        );
        final PlainActionFuture<Void> future = new PlainActionFuture<>();
        final Cancellable cancellable = getRestClient().performRequestAsync(request, new ResponseListener() {
            @Override
            public void onSuccess(Response response) {
                future.onResponse(null);
            }

            @Override
            public void onFailure(Exception exception) {
                future.onFailure(exception);
            }
        });

        assertFalse(future.isDone());
        awaitTaskWithPrefix(SnapshotsStatusAction.NAME);
        assertBusy(() -> assertTrue(repository.blocked()), 30L, TimeUnit.SECONDS);
        cancellable.cancel();
        assertAllCancellableTasksAreCancelled(SnapshotsStatusAction.NAME);
        repository.unblock();
        expectThrows(CancellationException.class, future::actionGet);

        assertAllTasksHaveFinished(SnapshotsStatusAction.NAME);
    }
}
