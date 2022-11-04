/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.admin.cluster.node.shutdown;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.transport.TransportRequest;

import java.io.IOException;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

public class NodeCheckShardsOnDataPathRequest extends TransportRequest {

    private final Set<ShardId> shardIds;
    @Nullable
    private final String customDataPath;

    public NodeCheckShardsOnDataPathRequest(Collection<ShardId> shardIds, String customDataPath) {
        this.shardIds = Set.copyOf(Objects.requireNonNull(shardIds));
        this.customDataPath = Objects.requireNonNull(customDataPath);
    }

    public NodeCheckShardsOnDataPathRequest(StreamInput in) throws IOException {
        super(in);
        this.shardIds = in.readSet(ShardId::new);
        this.customDataPath = in.readString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeCollection(shardIds, (o, value) -> value.writeTo(o));
        out.writeString(customDataPath);
    }

    public Set<ShardId> getShardIDs() {
        return shardIds;
    }

    public String getCustomDataPath() {
        return customDataPath;
    }
}
