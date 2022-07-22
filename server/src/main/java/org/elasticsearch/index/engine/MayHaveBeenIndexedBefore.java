/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.index.engine;

import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.common.lucene.uid.Versions;
import org.elasticsearch.index.VersionType;
import org.elasticsearch.index.engine.Engine.Index;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Quickly detects cases where {@link Engine.Index} operations must be unique
 * so we can add them to the index without performing slow uniqueness queries.
 */
public interface MayHaveBeenIndexedBefore {
    /**
     * Bootstrap state from commit data.
     */
    void bootstrap(Iterable<Map.Entry<String, String>> liveCommitData);

    long getMaxSeenAutoIdTimestamp();

    /**
     * {@code true} if it's valid to call {@link #mayHaveBeenIndexedBefore}
     * on the provided {@link Index}, false otherwise. This should be fast
     * an only rely on state from the {@link Index} and not rely on any
     * internal state.
     */
    boolean canOptimizeAddDocument(Index index);

    /**
     * Returns {@code true} if the indexing operation may have already be
     * processed by the engine. Note that it is OK to rarely return true even
     * if this is not the case. However a {@code false} return value must
     * always be correct.
     * <p>
     * This relies on state internal to the implementation and may modify
     * that state.
     */
    boolean mayHaveBeenIndexedBefore(Index index);

    void updateAutoIdTimestamp(long newTimestamp);

    void handleNonPrimary(Index index);

    void writerSegmentStats(SegmentsStats stats);

    void writeCommitData(Map<String, String> commitData);

    class Standard implements MayHaveBeenIndexedBefore {
        /**
         * Updated on bootstrap, recovery, and retry.
         */
        private final AtomicLong maxUnsafeAutoIdTimestamp = new AtomicLong(-1);
        private final AtomicLong maxSeenAutoIdTimestamp = new AtomicLong(-1);

        @Override
        public boolean canOptimizeAddDocument(Index index) {
            if (index.getAutoGeneratedIdTimestamp() == IndexRequest.UNSET_AUTO_GENERATED_TIMESTAMP) {
                return false;
            }
            assert index.getAutoGeneratedIdTimestamp() >= 0
                : "autoGeneratedIdTimestamp must be positive but was: " + index.getAutoGeneratedIdTimestamp();
            switch (index.origin()) {
                case PRIMARY:
                    assert (index.version() == Versions.MATCH_DELETED || index.version() == Versions.MATCH_ANY)
                        && index.versionType() == VersionType.INTERNAL : "version: " + index.version() + " type: " + index.versionType();
                    break;
                case PEER_RECOVERY, REPLICA:
                    assert index.version() == 1 && index.versionType() == null
                        : "version: " + index.version() + " type: " + index.versionType();
                    break;
                case LOCAL_TRANSLOG_RECOVERY, LOCAL_RESET:
                    assert index.isRetry();
                    break;
            }

            return true;
        }

        @Override
        public void bootstrap(Iterable<Map.Entry<String, String>> liveCommitData) {
            for (Map.Entry<String, String> entry : liveCommitData) {
                if (Engine.MAX_UNSAFE_AUTO_ID_TIMESTAMP_COMMIT_ID.equals(entry.getKey())) {
                    assert maxUnsafeAutoIdTimestamp.get() == -1
                        : "max unsafe timestamp was assigned already [" + maxUnsafeAutoIdTimestamp.get() + "]";
                    updateAutoIdTimestamp(Long.parseLong(entry.getValue()), true);
                }
            }
        }

        @Override
        public boolean mayHaveBeenIndexedBefore(Index index) {
            assert canOptimizeAddDocument(index);
            final boolean mayHaveBeenIndexBefore;
            if (index.isRetry()) {
                mayHaveBeenIndexBefore = true;
                updateAutoIdTimestamp(index.getAutoGeneratedIdTimestamp(), true);
                assert maxUnsafeAutoIdTimestamp.get() >= index.getAutoGeneratedIdTimestamp();
            } else {
                // in this case we force
                mayHaveBeenIndexBefore = maxUnsafeAutoIdTimestamp.get() >= index.getAutoGeneratedIdTimestamp();
                updateAutoIdTimestamp(index.getAutoGeneratedIdTimestamp(), false);
            }
            return mayHaveBeenIndexBefore;
        }

        @Override
        public long getMaxSeenAutoIdTimestamp() {
            return maxSeenAutoIdTimestamp.get();
        }

        @Override
        public void handleNonPrimary(Index index) {
            // needs to maintain the auto_id timestamp in case this replica becomes primary
            if (canOptimizeAddDocument(index)) {
                mayHaveBeenIndexedBefore(index);
            }
        }

        @Override
        public void updateAutoIdTimestamp(long newTimestamp) {
            updateAutoIdTimestamp(newTimestamp, true);
        }

        private void updateAutoIdTimestamp(long newTimestamp, boolean unsafe) {
            assert newTimestamp >= -1 : "invalid timestamp [" + newTimestamp + "]";
            maxSeenAutoIdTimestamp.updateAndGet(curr -> Math.max(curr, newTimestamp));
            if (unsafe) {
                maxUnsafeAutoIdTimestamp.updateAndGet(curr -> Math.max(curr, newTimestamp));
            }
            assert maxUnsafeAutoIdTimestamp.get() <= maxSeenAutoIdTimestamp.get();
        }

        @Override
        public void writerSegmentStats(SegmentsStats stats) {
            stats.updateMaxUnsafeAutoIdTimestamp(maxUnsafeAutoIdTimestamp.get());
        }

        @Override
        public void writeCommitData(Map<String, String> commitData) {
            commitData.put(Engine.MAX_UNSAFE_AUTO_ID_TIMESTAMP_COMMIT_ID, Long.toString(maxUnsafeAutoIdTimestamp.get()));
        }
    }
}
