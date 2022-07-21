/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.repositories.blobstore;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRunnable;
import org.elasticsearch.common.CheckedBiConsumer;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.repositories.SnapshotShardContext;

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;

import static org.elasticsearch.index.snapshots.blobstore.BlobStoreIndexShardSnapshot.FileInfo;

public final class ShardSnapshotWorkerPool {
    private static final Logger logger = LogManager.getLogger(ShardSnapshotWorkerPool.class);

    private final int maxWorkers;
    private final Object mutex = new Object();
    private final BlockingQueue<SnapshotShardContext> shardsToSnapshot = new LinkedBlockingQueue<>();
    private final BlockingQueue<SnapshotFileUpload> filesToSnapshot = new LinkedBlockingQueue<>();
    private final Executor executor;
    private final Consumer<SnapshotShardContext> shardSnapshotter;
    private final CheckedBiConsumer<SnapshotShardContext, FileInfo, IOException> fileSnapshotter;
    private volatile int workerCount = 0;

    public record SnapshotFileUpload(SnapshotShardContext context, FileInfo fileInfo, ActionListener<Void> listener) {}

    public ShardSnapshotWorkerPool(
        final int maxWorkers,
        final Executor executor,
        final Consumer<SnapshotShardContext> shardSnapshotter,
        final CheckedBiConsumer<SnapshotShardContext, FileInfo, IOException> fileSnapshotter
    ) {
        assert maxWorkers > 0;

        logger.info("starting shard snapshot worker pool of max size {}", maxWorkers);
        this.maxWorkers = maxWorkers;
        this.executor = executor;
        this.shardSnapshotter = shardSnapshotter;
        this.fileSnapshotter = fileSnapshotter;
    }

    public void enqueueShardSnapshot(final SnapshotShardContext context) {
        logger.trace("enqueuing shard snapshot task [snapshotID={}, indexID={}]", context.snapshotId(), context.indexId());
        synchronized (mutex) {
            shardsToSnapshot.add(context);
            ensureEnoughWorkers();
        }
    }

    public void enqueueFileUpload(final SnapshotFileUpload snapshotFileUpload) {
        logger.trace(
            "enqueuing shard snapshot file upload task [snapshotID={}, indexID={}, file={}]",
            snapshotFileUpload.context.snapshotId(),
            snapshotFileUpload.context.indexId(),
            snapshotFileUpload.fileInfo.name()
        );
        synchronized (mutex) {
            filesToSnapshot.add(snapshotFileUpload);
            ensureEnoughWorkers();
        }
    }

    private void ensureEnoughWorkers() {
        assert Thread.holdsLock(mutex);

        int workersToCreate = Math.min(maxWorkers - workerCount, Math.max(filesToSnapshot.size(), shardsToSnapshot.size()));
        if (workersToCreate > 0) {
            logger.debug("starting {} shard snapshot workers", workersToCreate);
        }
        while (workersToCreate > 0) {
            workerCount++;
            startWorker(UUIDs.base64UUID());
            workersToCreate--;
        }
        logger.debug("worker pool size is {}", workerCount);
    }

    private void workerDone() {
        synchronized (mutex) {
            assert workerCount > 0;

            workerCount--;
            ensureEnoughWorkers();
        }
    }

    public int size() {
        return workerCount;
    }

    private void startWorker(final String workerId) {
        logger.debug("starting snapshot pool worker {}", workerId);
        executor.execute(() -> {
            try {
                while (true) {
                    SnapshotShardContext context = shardsToSnapshot.poll();
                    if (context == null) {
                        logger.trace("[worker {}] shard snapshot queue is empty", workerId);
                        break;
                    }
                    shardSnapshotter.accept(context);
                }
                while (true) {
                    SnapshotFileUpload fileUploadTask = filesToSnapshot.poll();
                    if (fileUploadTask == null) {
                        logger.trace("[worker {}] file upload queue is empty", workerId);
                        break;
                    }
                    ActionRunnable.run(
                        fileUploadTask.listener,
                        () -> fileSnapshotter.accept(fileUploadTask.context(), fileUploadTask.fileInfo())
                    ).run();
                }
            } finally {
                logger.debug("[worker {}] worker is done", workerId);
                workerDone();
            }
        });
    }

}
