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

package org.elasticsearch.action.admin.indices.stats;

import org.elasticsearch.cluster.routing.ShardRouting;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.index.store.StoreStats;

import java.io.IOException;

public class DataStreamShardStats implements Writeable {

    private final ShardRouting shardRouting;
    private final StoreStats storeStats;
    private final long maxTimestamp;

    public DataStreamShardStats(ShardRouting shardRouting, StoreStats storeStats, long maxTimestamp) {
        this.shardRouting = shardRouting;
        this.storeStats = storeStats;
        this.maxTimestamp = maxTimestamp;
    }

    public DataStreamShardStats(StreamInput in) throws IOException {
        this.shardRouting = new ShardRouting(in);
        this.storeStats = new StoreStats(in);
        this.maxTimestamp = in.readVLong();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        shardRouting.writeTo(out);
        storeStats.writeTo(out);
        out.writeVLong(maxTimestamp);
    }

    public ShardRouting getShardRouting() {
        return shardRouting;
    }

    public StoreStats getStoreStats() {
        return storeStats;
    }

    public long getMaxTimestamp() {
        return maxTimestamp;
    }
}
