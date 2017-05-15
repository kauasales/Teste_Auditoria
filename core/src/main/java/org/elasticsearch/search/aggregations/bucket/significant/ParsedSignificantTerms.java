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

import org.elasticsearch.common.CheckedBiConsumer;
import org.elasticsearch.common.CheckedFunction;
import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentParserUtils;
import org.elasticsearch.search.aggregations.Aggregation;
import org.elasticsearch.search.aggregations.Aggregations;
import org.elasticsearch.search.aggregations.ParsedMultiBucketAggregation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

public abstract class ParsedSignificantTerms extends ParsedMultiBucketAggregation<ParsedSignificantTerms.ParsedBucket>
        implements SignificantTerms {

    private static final String SCORE = "score";
    private static final String BG_COUNT = "bg_count";

    protected long subsetSize;

    @Override
    public List<? extends SignificantTerms.Bucket> getBuckets() {
        return buckets;
    }

    @Override
    public SignificantTerms.Bucket getBucketByKey(String term) {
        for (SignificantTerms.Bucket bucket : getBuckets()) {
            if (bucket.getKeyAsString().equals(term)) {
                return bucket;
            }
        }
        return null;
    }

    @Override
    public Iterator<SignificantTerms.Bucket> iterator() {
        return buckets.stream().map(bucket -> (SignificantTerms.Bucket) bucket).collect(Collectors.toList()).iterator();
    }

    @Override
    protected XContentBuilder doXContentBody(XContentBuilder builder, Params params) throws IOException {
        builder.field(CommonFields.DOC_COUNT.getPreferredName(), subsetSize);
        builder.startArray(CommonFields.BUCKETS.getPreferredName());
        for (SignificantTerms.Bucket bucket : buckets) {
            bucket.toXContent(builder, params);
        }
        builder.endArray();
        return builder;
    }

    static void declareParsedSignificantTermsFields(final ObjectParser<? extends ParsedSignificantTerms, Void> objectParser,
                                     final CheckedFunction<XContentParser, ParsedSignificantTerms.ParsedBucket, IOException> bucketParser) {
        declareMultiBucketAggregationFields(objectParser, bucketParser::apply, bucketParser::apply);
        objectParser.declareLong((parsedTerms, value) -> parsedTerms.subsetSize = value , CommonFields.DOC_COUNT);
    }

    public abstract static class ParsedBucket extends ParsedMultiBucketAggregation.ParsedBucket implements SignificantTerms.Bucket {

        protected long subsetDf;
        protected long supersetDf;
        protected double score;

        @Override
        public long getDocCount() {
            return getSubsetDf();
        }

        @Override
        public long getSubsetDf() {
            return subsetDf;
        }

        @Override
        public long getSupersetDf() {
            return supersetDf;
        }

        @Override
        public double getSignificanceScore() {
            return score;
        }

        @Override
        public long getSupersetSize() {
            throw new UnsupportedOperationException();
        }

        @Override
        public long getSubsetSize() {
            throw new UnsupportedOperationException();
        }

        @Override
        public final XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            keyToXContent(builder);
            builder.field(CommonFields.DOC_COUNT.getPreferredName(), getDocCount());
            builder.field(SCORE, getSignificanceScore());
            builder.field(BG_COUNT, getSupersetDf());
            getAggregations().toXContentInternal(builder, params);
            builder.endObject();
            return builder;
        }

        protected abstract XContentBuilder keyToXContent(XContentBuilder builder) throws IOException;

        static <B extends ParsedBucket> B parseSignificantTermsBucketXContent(final XContentParser parser, final B bucket,
            final CheckedBiConsumer<XContentParser, B, IOException> keyConsumer) throws IOException {

            final List<Aggregation> aggregations = new ArrayList<>();
            XContentParser.Token token;
            String currentFieldName = parser.currentName();
            while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
                if (token == XContentParser.Token.FIELD_NAME) {
                    currentFieldName = parser.currentName();
                } else if (token.isValue()) {
                    if (CommonFields.KEY_AS_STRING.getPreferredName().equals(currentFieldName)) {
                        bucket.setKeyAsString(parser.text());
                    } else if (CommonFields.KEY.getPreferredName().equals(currentFieldName)) {
                        keyConsumer.accept(parser, bucket);
                    } else if (CommonFields.DOC_COUNT.getPreferredName().equals(currentFieldName)) {
                        long value = parser.longValue();
                        bucket.subsetDf = value;
                        bucket.setDocCount(value);
                    } else if (SCORE.equals(currentFieldName)) {
                        bucket.score = parser.longValue();
                    } else if (BG_COUNT.equals(currentFieldName)) {
                        bucket.supersetDf = parser.longValue();
                    }
                } else if (token == XContentParser.Token.START_OBJECT) {
                    aggregations.add(XContentParserUtils.parseTypedKeysObject(parser, Aggregation.TYPED_KEYS_DELIMITER, Aggregation.class));
                }
            }
            bucket.setAggregations(new Aggregations(aggregations));
            return bucket;
        }
    }
}
