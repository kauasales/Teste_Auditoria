/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.searchablesnapshots;

import org.elasticsearch.cluster.routing.ShardRouting;
import org.elasticsearch.cluster.routing.ShardRoutingState;
import org.elasticsearch.cluster.routing.TestShardRouting;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.repositories.IndexId;
import org.elasticsearch.snapshots.SnapshotId;
import org.elasticsearch.test.AbstractWireSerializingTestCase;
import org.elasticsearch.xpack.core.searchablesnapshots.SearchableSnapshotShardStats.CacheIndexInputStats;
import org.elasticsearch.xpack.core.searchablesnapshots.SearchableSnapshotShardStats.Counter;

import java.util.ArrayList;
import java.util.List;

public class SearchableSnapshotShardStatsTests extends AbstractWireSerializingTestCase<SearchableSnapshotShardStats> {

    @Override
    protected Writeable.Reader<SearchableSnapshotShardStats> instanceReader() {
        return SearchableSnapshotShardStats::new;
    }

    @Override
    protected SearchableSnapshotShardStats createTestInstance() {
        SnapshotId snapshotId = new SnapshotId(randomAlphaOfLength(5), randomAlphaOfLength(5));
        IndexId indexId = new IndexId(randomAlphaOfLength(5), randomAlphaOfLength(5));
        ShardRouting shardRouting = TestShardRouting.newShardRouting(randomAlphaOfLength(5), randomInt(10), randomAlphaOfLength(5),
            randomBoolean(), ShardRoutingState.STARTED);

        final List<CacheIndexInputStats> inputStats = new ArrayList<>();
        for (int j = 0; j < randomInt(20); j++) {
            inputStats.add(randomCacheIndexInputStats());
        }
        return new SearchableSnapshotShardStats(shardRouting, snapshotId, indexId, inputStats);
    }

    private CacheIndexInputStats randomCacheIndexInputStats() {
        return new CacheIndexInputStats(randomAlphaOfLength(10), randomNonNegativeLong(),
            randomNonNegativeLong(), randomNonNegativeLong(), randomNonNegativeLong(),
            randomCounter(), randomCounter(),
            randomCounter(), randomCounter(),
            randomCounter(), randomCounter(),
            randomCounter(), randomCounter(),
            randomCounter());
    }

    private Counter randomCounter() {
        return new Counter(randomLong(), randomLong(), randomLong(), randomLong());
    }
}
