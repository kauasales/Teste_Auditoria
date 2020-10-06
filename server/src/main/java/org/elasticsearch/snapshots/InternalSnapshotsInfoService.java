/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.snapshots;

import com.carrotsearch.hppc.cursors.ObjectCursor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.routing.RecoverySource;
import org.elasticsearch.cluster.routing.RerouteService;
import org.elasticsearch.cluster.routing.ShardRouting;
import org.elasticsearch.cluster.routing.ShardRoutingState;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.AbstractRunnable;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.repositories.IndexId;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.repositories.Repository;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class InternalSnapshotsInfoService implements ClusterStateListener, SnapshotsInfoService {

    public static final Setting<Integer> INTERNAL_SNAPSHOT_INFO_MAX_CONCURRENT_FETCHES_SETTING =
        Setting.intSetting("cluster.snapshot.info.max_concurrent_fetches", 5, 1,
            Setting.Property.Dynamic, Setting.Property.NodeScope);

    private static final Logger logger = LogManager.getLogger(InternalSnapshotsInfoService.class);

    private static final ActionListener<ClusterState> REROUTE_LISTENER = ActionListener.wrap(
        r -> logger.trace("reroute after snapshot shard size update completed"),
        e -> logger.debug("reroute after snapshot shard size update failed", e)
    );

    private final ThreadPool threadPool;
    private final Supplier<RepositoriesService> repositoriesService;
    private final Supplier<RerouteService> rerouteService;

    /** contains the snapshot shards for which the size is known **/
    private volatile ImmutableOpenMap<SnapshotShard, Long> knownSnapshotShardSizes;

    private volatile boolean isMaster;

    /** contains the snapshot shards for which the size is unknown and must be fetched (or is being fetched) **/
    private final Set<SnapshotShard> unknownSnapshotShards;

    /** a blocking queue used for concurrent fetching **/
    private final BlockingQueue<SnapshotShard> queue;

    private volatile int maxConcurrentFetches;
    private volatile int activeFetches;

    private final Object mutex;

    public InternalSnapshotsInfoService(
        final Settings settings,
        final ClusterService clusterService,
        final Supplier<RepositoriesService> repositoriesServiceSupplier,
        final Supplier<RerouteService> rerouteServiceSupplier
    ) {
        this.threadPool = clusterService.getClusterApplierService().threadPool();
        this.repositoriesService = repositoriesServiceSupplier;
        this.rerouteService = rerouteServiceSupplier;
        this.knownSnapshotShardSizes = ImmutableOpenMap.of();
        this.unknownSnapshotShards  = new LinkedHashSet<>();
        this.queue = new LinkedBlockingQueue<>();
        this.mutex = new Object();
        this.activeFetches = 0;
        this.maxConcurrentFetches = INTERNAL_SNAPSHOT_INFO_MAX_CONCURRENT_FETCHES_SETTING.get(settings);
        final ClusterSettings clusterSettings = clusterService.getClusterSettings();
        clusterSettings.addSettingsUpdateConsumer(INTERNAL_SNAPSHOT_INFO_MAX_CONCURRENT_FETCHES_SETTING, this::setMaxConcurrentFetches);
        if (DiscoveryNode.isMasterNode(settings)) {
            clusterService.addListener(this);
        }
    }

    private void setMaxConcurrentFetches(Integer maxConcurrentFetches) {
        this.maxConcurrentFetches = maxConcurrentFetches;
    }

    @Override
    public SnapshotShardSizeInfo snapshotShardSizes() {
        return new SnapshotShardSizeInfo(knownSnapshotShardSizes);
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        if (event.localNodeMaster()) {
            final Set<SnapshotShard> onGoingSnapshotRecoveries = listOfSnapshotShards(event.state());

            int unknownShards = 0;
            synchronized (mutex) {
                isMaster = true;
                for (SnapshotShard snapshotShard : onGoingSnapshotRecoveries) {
                    // check if already populated entry
                    if (knownSnapshotShardSizes.containsKey(snapshotShard) == false) {
                        // check if already fetching snapshot info in progress
                        if (unknownSnapshotShards.add(snapshotShard)) {
                            queue.add(snapshotShard);
                            unknownShards += 1;
                        }
                    }
                }
                // Clean up keys from knownSnapshotShardSizes that are no longer needed for recoveries
                cleanUpKnownSnapshotShardSizes(onGoingSnapshotRecoveries);
            }

            final int nbFetchers = Math.min(unknownShards, maxConcurrentFetches);
            for (int i = 0; i < nbFetchers; i++) {
                fetchNextSnapshotShard();
            }
        } else if (event.previousState().nodes().isLocalNodeElectedMaster()) {
            // TODO Maybe just clear out non-ongoing snapshot recoveries is the node is master eligible, so that we don't
            // have to repopulate the data over and over in an unstable master situation?
            synchronized (mutex) {
                // information only needed on current master
                knownSnapshotShardSizes = ImmutableOpenMap.of();
                isMaster = false;
            }
        }
    }

    private void fetchNextSnapshotShard() {
        synchronized (mutex) {
            if (activeFetches < maxConcurrentFetches) {
                try {
                    final SnapshotShard snapshotShard = queue.poll(0L, TimeUnit.MILLISECONDS);
                    if (snapshotShard != null) {
                        threadPool.generic().execute(new FetchingSnapshotShardSizeRunnable(snapshotShard));
                        activeFetches += 1;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.warn("snapshot shard size fetcher has been interrupted", e);
                }
            }
            assert assertNumberOfConcurrentFetches();
        }
    }

    private class FetchingSnapshotShardSizeRunnable extends AbstractRunnable {

        private final SnapshotShard snapshotShard;
        private boolean removed;

        FetchingSnapshotShardSizeRunnable(SnapshotShard snapshotShard) {
            super();
            this.snapshotShard = snapshotShard;
            this.removed = false;
        }

        @Override
        protected void doRun() throws Exception {
            final RepositoriesService repositories = repositoriesService.get();
            assert repositories != null;
            final Repository repository = repositories.repository(snapshotShard.snapshot.getRepository());

            logger.debug("fetching snapshot shard size for {}", snapshotShard);
            final long snapshotShardSize = repository.getShardSnapshotStatus(
                snapshotShard.snapshot().getSnapshotId(),
                snapshotShard.index(),
                snapshotShard.shardId()
            ).asCopy().getTotalSize();

            logger.debug("snapshot shard size for {}: {} bytes", snapshotShard, snapshotShardSize);

            boolean updated = false;
            synchronized (mutex) {
                removed = unknownSnapshotShards.remove(snapshotShard);
                assert removed : "snapshot shard to remove does not exist " + snapshotShardSize;
                if (isMaster) {
                    final ImmutableOpenMap.Builder<SnapshotShard, Long> newSnapshotShardSizes =
                        ImmutableOpenMap.builder(knownSnapshotShardSizes);
                    updated = newSnapshotShardSizes.put(snapshotShard, snapshotShardSize) == null;
                    assert updated : "snapshot shard size already exists for " + snapshotShard;
                    knownSnapshotShardSizes = newSnapshotShardSizes.build();
                }
                activeFetches -= 1;
                assert assertNumberOfConcurrentFetches();
            }
            if (updated) {
                rerouteService.get().reroute("snapshot shard size updated", Priority.HIGH, REROUTE_LISTENER);
            }
        }

        @Override
        public void onFailure(Exception e) {
            logger.warn(() -> new ParameterizedMessage("failed to retrieve shard size for {}", snapshotShard), e);
            synchronized (mutex) {
                if (removed == false) {
                    unknownSnapshotShards.remove(snapshotShard);
                }
                activeFetches -= 1;
                assert assertNumberOfConcurrentFetches();
            }
        }

        @Override
        public void onAfter() {
            fetchNextSnapshotShard();
        }
    }

    private void cleanUpKnownSnapshotShardSizes(Set<SnapshotShard> requiredSnapshotShards) {
        assert Thread.holdsLock(mutex);
        ImmutableOpenMap.Builder<SnapshotShard, Long> newSnapshotShardSizes = null;
        for (ObjectCursor<SnapshotShard> shard : knownSnapshotShardSizes.keys()) {
            if (requiredSnapshotShards.contains(shard.value) == false) {
                if (newSnapshotShardSizes == null) {
                    newSnapshotShardSizes = ImmutableOpenMap.builder(knownSnapshotShardSizes);
                }
                newSnapshotShardSizes.remove(shard.value);
            }
        }
        if (newSnapshotShardSizes != null) {
            knownSnapshotShardSizes = newSnapshotShardSizes.build();
        }
    }

    private boolean assertNumberOfConcurrentFetches() {
        assert activeFetches >= 0 : "active fetches should be greater than or equal to zero but got: " + activeFetches;
        assert activeFetches <= maxConcurrentFetches : activeFetches + " <= " + maxConcurrentFetches;
        return true;
    }

    // used in tests
    int numberOfUnknownSnapshotShardSizes() {
        synchronized (mutex) {
            return unknownSnapshotShards.size();
        }
    }

    // used in tests
    int numberOfKnownSnapshotShardSizes() {
        return knownSnapshotShardSizes.size();
    }

    private static Set<SnapshotShard> listOfSnapshotShards(final ClusterState state) {
        final Set<SnapshotShard> snapshotShards = new HashSet<>();
        for (ShardRouting shardRouting : state.routingTable().shardsWithState(ShardRoutingState.UNASSIGNED)) {
            if (shardRouting.primary() && shardRouting.recoverySource().getType() == RecoverySource.Type.SNAPSHOT) {
                final RecoverySource.SnapshotRecoverySource snapshotRecoverySource =
                    (RecoverySource.SnapshotRecoverySource) shardRouting.recoverySource();
                final SnapshotShard snapshotShard = new SnapshotShard(snapshotRecoverySource.snapshot(),
                    snapshotRecoverySource.index(), shardRouting.shardId());
                snapshotShards.add(snapshotShard);
            }
        }
        return Collections.unmodifiableSet(snapshotShards);
    }

    public static class SnapshotShard {

        private final Snapshot snapshot;
        private final IndexId index;
        private final ShardId shardId;

        public SnapshotShard(Snapshot snapshot, IndexId index, ShardId shardId) {
            this.snapshot = snapshot;
            this.index = index;
            this.shardId = shardId;
        }

        public Snapshot snapshot() {
            return snapshot;
        }

        public IndexId index() {
            return index;
        }

        public ShardId shardId() {
            return shardId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final SnapshotShard that = (SnapshotShard) o;
            return shardId.equals(that.shardId)
                && snapshot.equals(that.snapshot)
                && index.equals(that.index);
        }

        @Override
        public int hashCode() {
            return Objects.hash(snapshot, index, shardId);
        }

        @Override
        public String toString() {
            return "[" +
                "snapshot=" + snapshot +
                ", index=" + index +
                ", shard=" + shardId +
                ']';
        }
    }
}
