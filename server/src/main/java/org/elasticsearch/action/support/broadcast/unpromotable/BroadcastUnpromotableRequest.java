/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.support.broadcast.unpromotable;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.cluster.routing.IndexShardRoutingTable;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.index.shard.ShardId;

import java.io.IOException;
import java.util.Objects;

import static org.elasticsearch.action.ValidateActions.addValidationError;
import static org.elasticsearch.action.support.IndicesOptions.strictSingleIndexNoExpandForbidClosed;

/**
 * A request that is broadcast to the unpromotable assigned replicas of a primary.
 */
public class BroadcastUnpromotableRequest extends ActionRequest implements IndicesRequest {

    /**
     * Holds the index shard routing table that will be used by {@link TransportBroadcastUnpromotableAction} to broadcast the requests to
     * the unpromotable replicas. The routing table is not serialized over the wire, and will be null on the other end of the wire.
     * For this reason, the field is package-private.
     */
    final @Nullable IndexShardRoutingTable indexShardRoutingTable;

    protected final String[] indices;
    protected final ShardId shardId;

    public BroadcastUnpromotableRequest(StreamInput in) throws IOException {
        super(in);
        indexShardRoutingTable = null;
        indices = new String[] { in.readString() };
        shardId = new ShardId(in);
    }

    public BroadcastUnpromotableRequest(IndexShardRoutingTable indexShardRoutingTable) {
        this.indexShardRoutingTable = Objects.requireNonNull(indexShardRoutingTable, "index shard routing table is null");
        this.indices = new String[] { indexShardRoutingTable.shardId().getIndex().getName() };
        this.shardId = indexShardRoutingTable.shardId();
    }

    public ShardId shardId() {
        return shardId;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (shardId == null) {
            validationException = addValidationError("shard id is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(indices[0]);
        out.writeWriteable(shardId);
    }

    @Override
    public String toString() {
        return "BroadcastUnpromotableRequest{shardId=" + shardId() + '}';
    }

    @Override
    public String getDescription() {
        return toString();
    }

    @Override
    public String[] indices() {
        return indices;
    }

    @Override
    public IndicesOptions indicesOptions() {
        return strictSingleIndexNoExpandForbidClosed();
    }
}
