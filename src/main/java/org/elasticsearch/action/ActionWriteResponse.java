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

package org.elasticsearch.action;

import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Streamable;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentBuilderString;
import org.elasticsearch.rest.RestStatus;

import java.io.IOException;

/**
 * Base class for write action responses.
 */
public abstract class ActionWriteResponse extends ActionResponse {

    public final static ActionWriteResponse.ShardInfo.Failure[] EMPTY = new ActionWriteResponse.ShardInfo.Failure[0];

    private ShardInfo shardInfo;

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        shardInfo = ActionWriteResponse.ShardInfo.readShardInfo(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        shardInfo.writeTo(out);
    }

    public ShardInfo getShardInfo() {
        return shardInfo;
    }

    public void setShardInfo(ShardInfo shardInfo) {
        this.shardInfo = shardInfo;
    }

    public static class ShardInfo implements Streamable, ToXContent {

        private int total;
        private int successful;
        private int pending;
        private Failure[] failures = EMPTY;

        public ShardInfo() {
        }

        public ShardInfo(int total, int successful, int pending, Failure... failures) {
            assert total >= 0 && successful >= 0 && pending >= 0;
            this.total = total;
            this.successful = successful;
            this.pending = pending;
            this.failures = failures;
        }

        /**
         * @return the total number of shards the write should go to.
         */
        public int getTotal() {
            return total;
        }

        /**
         * @return the total number of shards the write succeeded on.
         */
        public int getSuccessful() {
            return successful;
        }

        /**
         * @return the total number of shards a write is still to be performed on at the time this response was
         * created. Typically this will only contain 0, but when async replication is used this number is higher than 0.
         */
        public int getPending() {
            return pending;
        }

        /**
         * @return The total number of replication failures.
         */
        public int getFailed() {
            return failures.length;
        }

        /**
         * @return The replication failures that have been captured in the case writes have failed on replica shards.
         */
        public Failure[] getFailures() {
            return failures;
        }

        public RestStatus status() {
            RestStatus status = RestStatus.OK;
            for (Failure failure : failures) {
                if (failure.primary() && failure.status().getStatus() > status.getStatus()) {
                    status = failure.status();
                }
            }
            return status;
        }

        @Override
        public void readFrom(StreamInput in) throws IOException {
            total = in.readVInt();
            successful = in.readVInt();
            pending = in.readVInt();
            int size = in.readVInt();
            failures = new Failure[size];
            for (int i = 0; i < size; i++) {
                Failure failure = new Failure();
                failure.readFrom(in);
                failures[i] = failure;
            }
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeVInt(total);
            out.writeVInt(successful);
            out.writeVInt(pending);
            out.writeVInt(failures.length);
            for (Failure failure : failures) {
                failure.writeTo(out);
            }
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject(Fields._SHARDS);
            builder.field(Fields.TOTAL, total);
            builder.field(Fields.SUCCESSFUL, successful);
            if (pending > 0) {
                builder.field(Fields.PENDING, pending);
            }
            builder.field(Fields.FAILED, getFailed());
            if (failures.length > 0) {
                builder.startArray(Fields.FAILURES);
                for (Failure failure : failures) {
                    failure.toXContent(builder, params);
                }
                builder.endArray();
            }
            builder.endObject();
            return builder;
        }

        public static ShardInfo readShardInfo(StreamInput in) throws IOException {
            ShardInfo shardInfo = new ShardInfo();
            shardInfo.readFrom(in);
            return shardInfo;
        }

        public static class Failure implements ShardOperationFailedException, ToXContent {

            private String index;
            private int shardId;
            private String nodeId;
            private String reason;
            private RestStatus status;
            private boolean primary;

            public Failure(String index, int shardId, @Nullable String nodeId, String reason, RestStatus status, boolean primary) {
                this.index = index;
                this.shardId = shardId;
                this.nodeId = nodeId;
                this.reason = reason;
                this.status = status;
                this.primary = primary;
            }

            Failure() {
            }

            /**
             * @return On what index the failure occurred.
             */
            public String index() {
                return index;
            }

            /**
             * @return On what shard id the failure occurred.
             */
            public int shardId() {
                return shardId;
            }

            /**
             * @return On what node the failure occurred.
             */
            @Nullable
            public String nodeId() {
                return nodeId;
            }

            /**
             * @return A text description of the failure
             */
            public String reason() {
                return reason;
            }

            /**
             * @return The status to report if this failure was a primary failure.
             */
            public RestStatus status() {
                return status;
            }

            /**
             * @return Whether this failure occurred on a primary shard.
             * (this only reports true for delete by query)
             */
            public boolean primary() {
                return primary;
            }

            @Override
            public void readFrom(StreamInput in) throws IOException {
                index = in.readString();
                shardId = in.readVInt();
                nodeId = in.readOptionalString();
                reason = in.readString();
                status = RestStatus.readFrom(in);
                primary = in.readBoolean();
            }

            @Override
            public void writeTo(StreamOutput out) throws IOException {
                out.writeString(index);
                out.writeVInt(shardId);
                out.writeOptionalString(nodeId);
                out.writeString(reason);
                RestStatus.writeTo(out, status);
                out.writeBoolean(primary);
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
                builder.startObject();
                builder.field(Fields._INDEX, index);
                builder.field(Fields._SHARD, shardId);
                builder.field(Fields._NODE, nodeId);
                builder.field(Fields.REASON, reason);
                builder.field(Fields.STATUS, status);
                builder.field(Fields.PRIMARY, primary);
                builder.endObject();
                return builder;
            }

            private static class Fields {

                private static final XContentBuilderString _INDEX = new XContentBuilderString("_index");
                private static final XContentBuilderString _SHARD = new XContentBuilderString("_shard");
                private static final XContentBuilderString _NODE = new XContentBuilderString("_node");
                private static final XContentBuilderString REASON = new XContentBuilderString("reason");
                private static final XContentBuilderString STATUS = new XContentBuilderString("status");
                private static final XContentBuilderString PRIMARY = new XContentBuilderString("primary");

            }
        }

        private static class Fields {

            private static final XContentBuilderString _SHARDS = new XContentBuilderString("_shards");
            private static final XContentBuilderString TOTAL = new XContentBuilderString("total");
            private static final XContentBuilderString SUCCESSFUL = new XContentBuilderString("successful");
            private static final XContentBuilderString PENDING = new XContentBuilderString("pending");
            private static final XContentBuilderString FAILED = new XContentBuilderString("failed");
            private static final XContentBuilderString FAILURES = new XContentBuilderString("failures");

        }
    }
}
