/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.ml.inference.pytorch.results;

import org.elasticsearch.xcontent.ConstructingObjectParser;
import org.elasticsearch.xcontent.ParseField;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;

import java.io.IOException;

public record ThreadSettings(int numThreadsPerAllocation, int numAllocations, String requestId) implements ToXContentObject {

    private static final ParseField NUM_ALLOCATIONS = new ParseField("num_threads_per_allocation");
    private static final ParseField NUM_THREADS_PER_ALLOCATION = new ParseField("num_allocations");

    public static ConstructingObjectParser<ThreadSettings, Void> PARSER = new ConstructingObjectParser<>(
        "thread_settings",
        a -> new ThreadSettings((int) a[0], (int) a[1], (String) a[2])
    );

    static {
        PARSER.declareInt(ConstructingObjectParser.constructorArg(), NUM_THREADS_PER_ALLOCATION);
        PARSER.declareInt(ConstructingObjectParser.constructorArg(), NUM_ALLOCATIONS);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), PyTorchResult.REQUEST_ID);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NUM_THREADS_PER_ALLOCATION.getPreferredName(), numThreadsPerAllocation);
        builder.field(NUM_ALLOCATIONS.getPreferredName(), numAllocations);
        if (requestId != null) {
            builder.field(PyTorchResult.REQUEST_ID.getPreferredName(), requestId);
        }
        builder.endObject();
        return builder;
    }
}
