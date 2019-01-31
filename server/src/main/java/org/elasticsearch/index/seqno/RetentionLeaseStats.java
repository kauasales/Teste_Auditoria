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

package org.elasticsearch.index.seqno;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentFragment;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Collection;
import java.util.Objects;

/**
 * Represents retention lease stats.
 */
public final class RetentionLeaseStats implements ToXContentFragment, Writeable {

    private final Collection<RetentionLease> leases;

    /**
     * The underlying retention leases backing this stats object.
     *
     * @return the leases
     */
    public Collection<RetentionLease> leases() {
        return leases;
    }

    /**
     * Constructs a new retention lease stats object from the specified leases.
     *
     * @param leases the leases
     */
    public RetentionLeaseStats(final Collection<RetentionLease> leases) {
        this.leases = Objects.requireNonNull(leases);
    }

    /**
     * Constructs a new retention lease stats object from a stream. The retention lease stats should have been written via
     * {@link #writeTo(StreamOutput)}.
     *
     * @param in the stream to construct the retention lease stats from
     * @throws IOException if an I/O exception occurs reading from the stream
     */
    public RetentionLeaseStats(final StreamInput in) throws IOException {
        leases = in.readList(RetentionLease::new);
    }

    /**
     * Writes a retention lease stats object to a stream in a manner suitable for later reconstruction via
     * {@link #RetentionLeaseStats(StreamInput)} (StreamInput)}.
     *
     * @param out the stream to write the retention lease stats to
     * @throws IOException if an I/O exception occurs writing to the stream
     */
    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeCollection(leases);
    }

    /**
     * Converts the retention lease stats to {@link org.elasticsearch.common.xcontent.XContent} using the specified builder and pararms.
     *
     * @param builder the builder
     * @param params  the params
     * @return the builder that these retention leases were converted to {@link org.elasticsearch.common.xcontent.XContent} into
     * @throws IOException if an I/O exception occurs writing to the builder
     */
    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject("retention_leases");
        {
            builder.startArray("leases");
            {
                for (final RetentionLease retentionLease : leases) {
                    builder.startObject();
                    {
                        builder.field("id", retentionLease.id());
                        builder.field("retaining_seq_no", retentionLease.retainingSequenceNumber());
                        builder.field("timestamp", retentionLease.timestamp());
                        builder.field("source", retentionLease.source());
                    }
                    builder.endObject();
                }
            }
            builder.endArray();
        }
        builder.endObject();
        return builder;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final RetentionLeaseStats that = (RetentionLeaseStats) o;
        return Objects.equals(leases, that.leases);
    }

    @Override
    public int hashCode() {
        return Objects.hash(leases);
    }

}
