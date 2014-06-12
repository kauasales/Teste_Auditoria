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
package org.elasticsearch.search.aggregations.bucket.global;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.search.aggregations.AggregationStreams;
import org.elasticsearch.search.aggregations.InternalAggregations;
import org.elasticsearch.search.aggregations.bucket.InternalSingleBucketAggregation;

import java.io.IOException;

/**
 * A global scope get (the document set on which we aggregate is all documents in the search context (ie. index + type)
 * regardless the query.
 */
public class InternalGlobal extends InternalSingleBucketAggregation implements Global {

    public final static Type TYPE = new Type("global");

    public final static AggregationStreams.Stream STREAM = new AggregationStreams.Stream() {
        @Override
        public InternalGlobal readResult(StreamInput in) throws IOException {
            InternalGlobal result = new InternalGlobal();
            result.readFrom(in);
            return result;
        }
    };

    public static void registerStreams() {
        AggregationStreams.registerStream(STREAM, TYPE.stream());
    }

    InternalGlobal() {} // for serialization

    InternalGlobal(String name, long docCount, InternalAggregations aggregations, byte[] metaData) {
        super(name, docCount, aggregations, metaData);
    }

    @Override
    public Type type() {
        return TYPE;
    }
}
