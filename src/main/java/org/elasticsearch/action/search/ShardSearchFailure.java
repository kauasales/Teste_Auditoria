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

package org.elasticsearch.action.search;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.action.ShardOperationFailedException;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.SearchException;
import org.elasticsearch.search.SearchShardTarget;

import java.io.IOException;

import static org.elasticsearch.search.SearchShardTarget.readSearchShardTarget;

/**
 * Represents a failure to search on a specific shard.
 */
public class ShardSearchFailure implements ShardOperationFailedException, ToXContent {

    public static final ShardSearchFailure[] EMPTY_ARRAY = new ShardSearchFailure[0];

    private SearchShardTarget shardTarget;
    private String reason;
    private RestStatus status;

    ToXContent stucturedExplanation;

    private ShardSearchFailure() {

    }

    public ShardSearchFailure(Throwable t) {
        this(t, null);
    }
    
    public ShardSearchFailure(Throwable t, @Nullable SearchShardTarget shardTarget) {
        Throwable actual = ExceptionsHelper.unwrapCause(t);
        if (actual != null && actual instanceof SearchException) {
            this.shardTarget = ((SearchException) actual).shard();
        } else if (shardTarget != null) {
            this.shardTarget = shardTarget;
        }
        this.stucturedExplanation = ExceptionsHelper.getAnyXContentExplanation(actual);
        if (actual != null && actual instanceof ElasticsearchException) {
            status = ((ElasticsearchException) actual).status();
        } else {
            status = RestStatus.INTERNAL_SERVER_ERROR;
        }
        this.reason = ExceptionsHelper.detailedMessage(t);
    }

    public ShardSearchFailure(String reason, SearchShardTarget shardTarget) {
        this(reason, shardTarget, RestStatus.INTERNAL_SERVER_ERROR);
    }

    public ShardSearchFailure(String reason, SearchShardTarget shardTarget, RestStatus status) {
        this.shardTarget = shardTarget;
        this.reason = reason;
        this.status = status;
    }

    /**
     * The search shard target the failure occurred on.
     */
    @Nullable
    public SearchShardTarget shard() {
        return this.shardTarget;
    }

    public RestStatus status() {
        return this.status;
    }

    /**
     * The index the search failed on.
     */
    @Override
    public String index() {
        if (shardTarget != null) {
            return shardTarget.index();
        }
        return null;
    }

    /**
     * The shard id the search failed on.
     */
    @Override
    public int shardId() {
        if (shardTarget != null) {
            return shardTarget.shardId();
        }
        return -1;
    }

    /**
     * The reason of the failure.
     */
    public String reason() {
        return this.reason;
    }

    @Override
    public String toString() {
        return "shard [" + (shardTarget == null ? "_na" : shardTarget) + "], reason [" + reason + "]";
    }

    public static ShardSearchFailure readShardSearchFailure(StreamInput in) throws IOException {
        ShardSearchFailure shardSearchFailure = new ShardSearchFailure();
        shardSearchFailure.readFrom(in);
        return shardSearchFailure;
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        if (in.readBoolean()) {
            shardTarget = readSearchShardTarget(in);
        }
        reason = in.readString();
        status = RestStatus.readFrom(in);
        if (in.getVersion().onOrAfter(Version.V_1_5_0)) {
            if (in.readBoolean()) {
                stucturedExplanation = new UserErrorReport(in.readBytesReference());
            }
        }
    }

    // This class is used to hold XContent-serialized error messages that
    // originated from exceptions and is only required when ShardSearchFailure 
    // objects are streamed in order to report bulk failures 
    private static final class UserErrorReport implements ToXContent {
        private BytesReference reportSource;

        public UserErrorReport(BytesReference bytesReference) {
            this.reportSource = bytesReference;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            XContentHelper.writeDirect(reportSource, builder, params);
            return builder;
        }

    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        if (shardTarget == null) {
            out.writeBoolean(false);
        } else {
            out.writeBoolean(true);
            shardTarget.writeTo(out);
        }
        out.writeString(reason);
        RestStatus.writeTo(out, status);

        if (out.getVersion().onOrAfter(Version.V_1_5_0)) {
            // Write any report that relates to a user error
            out.writeBoolean(stucturedExplanation != null);
            if (stucturedExplanation != null) {
                BytesStreamOutput bStream = new BytesStreamOutput();
                XContentBuilder builder = XContentFactory.jsonBuilder(bStream);
                builder.startObject();
                stucturedExplanation.toXContent(builder, ToXContent.EMPTY_PARAMS);
                builder.endObject();
                builder.close();
                BytesReference br = bStream.bytes();
                out.writeBytesReference(br);
            }
        }

    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        if (stucturedExplanation != null) {
            stucturedExplanation.toXContent(builder, params);
        }
        return builder;
    }

    public boolean hasXContent() {
        return stucturedExplanation != null;
    }    
    
}
