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
package org.elasticsearch.search.aggregations.bucket.significant;

import org.apache.lucene.util.BytesRef;
import org.elasticsearch.Version;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.text.BytesText;
import org.elasticsearch.common.text.Text;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.search.aggregations.AggregationStreams;
import org.elasticsearch.search.aggregations.InternalAggregation;
import org.elasticsearch.search.aggregations.InternalAggregations;
import org.elasticsearch.search.aggregations.bucket.BucketStreamContext;
import org.elasticsearch.search.aggregations.bucket.BucketStreams;
import org.elasticsearch.search.aggregations.bucket.significant.heuristics.SignificanceHeuristic;
import org.elasticsearch.search.aggregations.bucket.significant.heuristics.SignificanceHeuristicStreams;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class SignificantStringTerms extends InternalSignificantTerms {

    public static final InternalAggregation.Type TYPE = new Type("significant_terms", "sigsterms");

    public static final AggregationStreams.Stream STREAM = new AggregationStreams.Stream() {
        @Override
        public SignificantStringTerms readResult(StreamInput in) throws IOException {
            SignificantStringTerms buckets = new SignificantStringTerms();
            buckets.readFrom(in);
            return buckets;
        }
    };

    private final static BucketStreams.Stream<Bucket> BUCKET_STREAM = new BucketStreams.Stream<Bucket>() {
        @Override
        public Bucket readResult(StreamInput in, BucketStreamContext context) throws IOException {
            Bucket buckets = new Bucket((long) context.attributes().get("subsetSize"), (long) context.attributes().get("supersetSize"));
            buckets.readFrom(in);
            return buckets;
        }

        @Override
        public BucketStreamContext getBucketStreamContext(Bucket bucket) {
            BucketStreamContext context = new BucketStreamContext();
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("subsetSize", bucket.subsetSize);
            attributes.put("supersetSize", bucket.supersetSize);
            context.attributes(attributes);
            return context;
        }
    };

    public static void registerStream() {
        AggregationStreams.registerStream(STREAM, TYPE.stream());
        BucketStreams.registerStream(BUCKET_STREAM, TYPE.stream());
    }

    public static void registerStreams() {
        AggregationStreams.registerStream(STREAM, TYPE.stream());
    }

    public static class Bucket extends InternalSignificantTerms.Bucket {

        BytesRef termBytes;

        public Bucket(long subsetSize, long supersetSize) {
            // for serialization
            super(subsetSize, supersetSize);
        }

        public Bucket(BytesRef term, long subsetDf, long subsetSize, long supersetDf, long supersetSize, InternalAggregations aggregations) {
            super(subsetDf, subsetSize, supersetDf, supersetSize, aggregations);
            this.termBytes = term;
        }

        @Override
        public Text getKeyAsText() {
            return new BytesText(new BytesArray(termBytes));
        }

        @Override
        public Number getKeyAsNumber() {
            // this method is needed for scripted numeric aggregations
            return Double.parseDouble(termBytes.utf8ToString());
        }

        @Override
        int compareTerm(SignificantTerms.Bucket other) {
            return BytesRef.getUTF8SortedAsUnicodeComparator().compare(termBytes, ((Bucket) other).termBytes);
        }

        @Override
        public String getKey() {
            return termBytes.utf8ToString();
        }

        @Override
        Bucket newBucket(long subsetDf, long subsetSize, long supersetDf, long supersetSize, InternalAggregations aggregations) {
            return new Bucket(termBytes, subsetDf, subsetSize, supersetDf, supersetSize, aggregations);
        }

        @Override
        public void readFrom(StreamInput in) throws IOException {
            termBytes = in.readBytesRef();
            subsetDf = in.readVLong();
            supersetDf = in.readVLong();
            aggregations = InternalAggregations.readAggregations(in);
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeBytesRef(termBytes);
            out.writeVLong(subsetDf);
            out.writeVLong(supersetDf);
            aggregations.writeTo(out);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.utf8Field(CommonFields.KEY, termBytes);
            builder.field(CommonFields.DOC_COUNT, getDocCount());
            builder.field("score", score);
            builder.field("bg_count", supersetDf);
            aggregations.toXContentInternal(builder, params);
            builder.endObject();
            return builder;
        }
    }

    SignificantStringTerms() {} // for serialization

    public SignificantStringTerms(long subsetSize, long supersetSize, String name, int requiredSize,
            long minDocCount, SignificanceHeuristic significanceHeuristic, List<InternalSignificantTerms.Bucket> buckets) {
        super(subsetSize, supersetSize, name, requiredSize, minDocCount, significanceHeuristic, buckets);
    }

    @Override
    public Type type() {
        return TYPE;
    }

    @Override
    InternalSignificantTerms newAggregation(long subsetSize, long supersetSize,
            List<InternalSignificantTerms.Bucket> buckets) {
        return new SignificantStringTerms(subsetSize, supersetSize, getName(), requiredSize, minDocCount, significanceHeuristic, buckets);
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        this.name = in.readString();
        this.requiredSize = readSize(in);
        this.minDocCount = in.readVLong();
        this.subsetSize = in.readVLong();
        this.supersetSize = in.readVLong();
        significanceHeuristic = SignificanceHeuristicStreams.read(in);
        int size = in.readVInt();
        List<InternalSignificantTerms.Bucket> buckets = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            Bucket bucket = new Bucket(subsetSize, supersetSize);
            bucket.readFrom(in);
            bucket.updateScore(significanceHeuristic);
            buckets.add(bucket);
        }
        this.buckets = buckets;
        this.bucketMap = null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        writeSize(requiredSize, out);
        out.writeVLong(minDocCount);
        out.writeVLong(subsetSize);
        out.writeVLong(supersetSize);
        if (out.getVersion().onOrAfter(Version.V_1_3_0)) {
            significanceHeuristic.writeTo(out);
        }
        out.writeVInt(buckets.size());
        for (InternalSignificantTerms.Bucket bucket : buckets) {
            bucket.writeTo(out);
        }
    }

    @Override
    public XContentBuilder doXContentBody(XContentBuilder builder, Params params) throws IOException {
        builder.field("doc_count", subsetSize);
        builder.startArray(CommonFields.BUCKETS);
        for (InternalSignificantTerms.Bucket bucket : buckets) {
            //There is a condition (presumably when only one shard has a bucket?) where reduce is not called
            // and I end up with buckets that contravene the user's min_doc_count criteria in my reducer
            if (bucket.subsetDf >= minDocCount) {
                bucket.toXContent(builder, params);
            }
        }
        builder.endArray();
        return builder;
    }

}
