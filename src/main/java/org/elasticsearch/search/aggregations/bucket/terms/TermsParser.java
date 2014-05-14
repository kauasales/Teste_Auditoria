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
package org.elasticsearch.search.aggregations.bucket.terms;

import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.search.aggregations.Aggregator;
import org.elasticsearch.search.aggregations.AggregatorFactory;
import org.elasticsearch.search.aggregations.bucket.terms.support.IncludeExclude;
import org.elasticsearch.search.aggregations.support.ValuesSourceParser;
import org.elasticsearch.search.internal.SearchContext;

import java.io.IOException;

/**
 *
 */
public class TermsParser implements Aggregator.Parser {

    @Override
    public String type() {
        return StringTerms.TYPE.name();
    }

    @Override
    public AggregatorFactory parse(String aggregationName, XContentParser parser, SearchContext context) throws IOException {
        TermsParametersParser aggParser = new TermsParametersParser();
        ValuesSourceParser vsParser = ValuesSourceParser.any(aggregationName, StringTerms.TYPE, context)
                .scriptable(true)
                .formattable(true)
                .requiresSortedValues(true)
                .requiresUniqueValues(true)
                .build();
        IncludeExclude.Parser incExcParser = new IncludeExclude.Parser(aggregationName, StringTerms.TYPE, context);
        aggParser.parse(aggregationName, parser, context, vsParser, incExcParser);

        TermsAggregator.BucketCountThresholds bucketCountThresholds = aggParser.getBucketCountThresholds();
        if (bucketCountThresholds.getShardSize() == 0) {
            bucketCountThresholds.setShardSize(Integer.MAX_VALUE);
        }
        if (bucketCountThresholds.getRequiredSize() == 0) {
            bucketCountThresholds.setRequiredSize(Integer.MAX_VALUE);
        }
        bucketCountThresholds.ensureValidity();
        InternalOrder order = resolveOrder(aggParser.getOrderKey(), aggParser.isOrderAsc());
        return new TermsAggregatorFactory(aggregationName, vsParser.config(), order, bucketCountThresholds, aggParser.getIncludeExclude(), aggParser.getExecutionHint());
    }

    static InternalOrder resolveOrder(String key, boolean asc) {
        if ("_term".equals(key)) {
            return asc ? InternalOrder.TERM_ASC : InternalOrder.TERM_DESC;
        }
        if ("_count".equals(key)) {
            return asc ? InternalOrder.COUNT_ASC : InternalOrder.COUNT_DESC;
        }
        return new InternalOrder.Aggregation(key, asc);
    }

}
