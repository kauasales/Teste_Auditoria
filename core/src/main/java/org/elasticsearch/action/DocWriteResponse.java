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

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentBuilderString;
import org.elasticsearch.index.shard.ShardId;

import java.io.IOException;

/**
 * A based class for the response of a write operation that involves are a single doc
 */
public abstract class DocWriteResponse extends ReplicationResponse implements ToXContent {

    private ShardId shardId;
    private String id;
    private String type;
    private long version;
    private long seqNo;

    public DocWriteResponse(ShardId shardId, String type, String id, long seqNo, long version) {
        this.shardId = shardId;
        this.type = type;
        this.id = id;
        this.seqNo = seqNo;
        this.version = version;
    }

    public DocWriteResponse() {

    }

    /**
     * The index the document was changed in.
     */
    public String getIndex() {
        return this.shardId.getIndex();
    }


    /**
     * The exact shard the document was changed in.
     */
    public ShardId getShardId() {
        return this.shardId;
    }

    /**
     * The type of the document changed.
     */
    public String getType() {
        return this.type;
    }

    /**
     * The id of the document changed.
     */
    public String getId() {
        return this.id;
    }

    /**
     * Returns the current version of the doc.
     */
    public long getVersion() {
        return this.version;
    }

    /**
     * Returns the sequence number assigned for this change. Returns -1L if the operation wasn't
     * performed (i.e., an update operation that resulted in a NOOP).
     */
    public long getSeqNo() {
        return seqNo;
    }


    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        shardId = ShardId.readShardId(in);
        type = in.readString();
        id = in.readString();
        version = in.readLong();
        seqNo = in.readLong();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        shardId.writeTo(out);
        out.writeString(type);
        out.writeString(id);
        out.writeLong(version);
        out.writeLong(seqNo);
    }

    static final class Fields {
        static final XContentBuilderString _INDEX = new XContentBuilderString("_index");
        static final XContentBuilderString _TYPE = new XContentBuilderString("_type");
        static final XContentBuilderString _ID = new XContentBuilderString("_id");
        static final XContentBuilderString _VERSION = new XContentBuilderString("_version");
        static final XContentBuilderString _SHARD_ID = new XContentBuilderString("_shard_id");
        static final XContentBuilderString _SEQ_NO = new XContentBuilderString("_seq_no");
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        ReplicationResponse.ShardInfo shardInfo = getShardInfo();
        builder.field(Fields._INDEX, getIndex())
                .field(Fields._TYPE, getType())
                .field(Fields._ID, getId())
                .field(Fields._VERSION, getVersion());
        //nocommit: i'm not sure we want to expose it in the api but it will be handy for debugging while we work...
        builder.field(Fields._SHARD_ID, shardId.id());
        if (getSeqNo() >= 0) {
            builder.field(Fields._SEQ_NO, getSeqNo());
        }
        shardInfo.toXContent(builder, params);
        return builder;
    }
}
