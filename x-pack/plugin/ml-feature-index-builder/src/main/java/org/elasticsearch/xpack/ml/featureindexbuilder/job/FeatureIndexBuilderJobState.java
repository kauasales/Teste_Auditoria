/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.ml.featureindexbuilder.job;

import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.persistent.PersistentTaskState;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.xpack.core.indexing.IndexerState;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

public class FeatureIndexBuilderJobState implements Task.Status, PersistentTaskState {
    public static final String NAME = "xpack/feature_index_builder/job";

    private final IndexerState state;

    @Nullable
    private final SortedMap<String, Object> currentPosition;

    private static final ParseField STATE = new ParseField("job_state");
    private static final ParseField CURRENT_POSITION = new ParseField("current_position");

    @SuppressWarnings("unchecked")
    public static final ConstructingObjectParser<FeatureIndexBuilderJobState, Void> PARSER = new ConstructingObjectParser<>(NAME,
            args -> new FeatureIndexBuilderJobState((IndexerState) args[0], (HashMap<String, Object>) args[1]));

    static {
        PARSER.declareField(constructorArg(), p -> {
            if (p.currentToken() == XContentParser.Token.VALUE_STRING) {
                return IndexerState.fromString(p.text());
            }
            throw new IllegalArgumentException("Unsupported token [" + p.currentToken() + "]");

        }, STATE, ObjectParser.ValueType.STRING);
        PARSER.declareField(optionalConstructorArg(), p -> {
            if (p.currentToken() == XContentParser.Token.START_OBJECT) {
                return p.map();
            }
            if (p.currentToken() == XContentParser.Token.VALUE_NULL) {
                return null;
            }
            throw new IllegalArgumentException("Unsupported token [" + p.currentToken() + "]");
        }, CURRENT_POSITION, ObjectParser.ValueType.VALUE_OBJECT_ARRAY);
    }

    public FeatureIndexBuilderJobState(IndexerState state, @Nullable Map<String, Object> position) {
        this.state = state;
        this.currentPosition = Collections.unmodifiableSortedMap(position == null ? null : new TreeMap<>(position));
    }

    public FeatureIndexBuilderJobState(StreamInput in) throws IOException {
        state = IndexerState.fromStream(in);
        currentPosition = in.readBoolean() ? Collections.unmodifiableSortedMap(new TreeMap<>(in.readMap())) : null;
    }

    public IndexerState getJobState() {
        return state;
    }

    public Map<String, Object> getPosition() {
        return currentPosition;
    }

    public static FeatureIndexBuilderJobState fromXContent(XContentParser parser) {
        try {
            return PARSER.parse(parser, null);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(STATE.getPreferredName(), state.value());
        if (currentPosition != null) {
            builder.field(CURRENT_POSITION.getPreferredName(), currentPosition);
        }
        builder.endObject();
        return builder;
    }

    @Override
    public String getWriteableName() {
        return NAME;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        state.writeTo(out);
        out.writeBoolean(currentPosition != null);
        if (currentPosition != null) {
            out.writeMap(currentPosition);
        }
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (other == null || getClass() != other.getClass()) {
            return false;
        }

        FeatureIndexBuilderJobState that = (FeatureIndexBuilderJobState) other;

        return Objects.equals(this.state, that.state) && Objects.equals(this.currentPosition, that.currentPosition);
    }

    @Override
    public int hashCode() {
        return Objects.hash(state, currentPosition);
    }
}