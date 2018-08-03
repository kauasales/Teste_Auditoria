/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.protocol.xpack.indexlifecycle;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class ExplainLifecycleResponse extends ActionResponse implements ToXContentObject {

    public static final ParseField INDICES_FIELD = new ParseField("indices");

    private Set<IndexLifecycleExplainResponse> indexResponses;

    @SuppressWarnings("unchecked")
    private static final ConstructingObjectParser<ExplainLifecycleResponse, Void> PARSER = new ConstructingObjectParser<>(
            "explain_lifecycle_response",
            a -> new ExplainLifecycleResponse(((List<IndexLifecycleExplainResponse>) a[0]).stream().collect(Collectors.toSet())));
    static {
        PARSER.declareNamedObjects(ConstructingObjectParser.constructorArg(), (p, c, n) -> IndexLifecycleExplainResponse.PARSER.apply(p, c),
                INDICES_FIELD);
    }

    public static ExplainLifecycleResponse fromXContent(XContentParser parser) {
        return PARSER.apply(parser, null);
    }

    public ExplainLifecycleResponse() {
    }

    public ExplainLifecycleResponse(Set<IndexLifecycleExplainResponse> indexResponses) {
        this.indexResponses = indexResponses;
    }

    public Set<IndexLifecycleExplainResponse> getIndexResponses() {
        return indexResponses;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startObject(INDICES_FIELD.getPreferredName());
        for (IndexLifecycleExplainResponse indexResponse : indexResponses) {
            builder.field(indexResponse.getIndex(), indexResponse);
        }
        builder.endObject();
        builder.endObject();
        return builder;
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        int size = in.readVInt();
        Set<IndexLifecycleExplainResponse> indexResponses = new HashSet<>(size);
        for (int i = 0; i < size; i++) {
            indexResponses.add(new IndexLifecycleExplainResponse(in));
        }
        this.indexResponses = indexResponses;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeVInt(indexResponses.size());
        for (IndexLifecycleExplainResponse e : indexResponses) {
            e.writeTo(out);
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(indexResponses);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj.getClass() != getClass()) {
            return false;
        }
        ExplainLifecycleResponse other = (ExplainLifecycleResponse) obj;
        return Objects.equals(indexResponses, other.indexResponses);
    }

    @Override
    public String toString() {
        return Strings.toString(this, true, true);
    }

}