/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.analytics.stringstats;

import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.search.DocValueFormat;
import org.elasticsearch.search.aggregations.AggregationExecutionException;
import org.elasticsearch.search.aggregations.Aggregator;
import org.elasticsearch.search.aggregations.AggregatorFactories;
import org.elasticsearch.search.aggregations.AggregatorFactory;
import org.elasticsearch.search.aggregations.pipeline.PipelineAggregator;
import org.elasticsearch.search.aggregations.support.AggregatorSupplier;
import org.elasticsearch.search.aggregations.support.ValuesSource;
import org.elasticsearch.search.aggregations.support.ValuesSourceAggregatorFactory;
import org.elasticsearch.search.aggregations.support.ValuesSourceConfig;
import org.elasticsearch.search.internal.SearchContext;

import java.io.IOException;
import java.util.List;
import java.util.Map;

class StringStatsAggregatorFactory extends ValuesSourceAggregatorFactory {
    static final StringStatsAggregatorSupplier IMPLEMENTATION = new StringStatsAggregatorSupplier() {
        @Override
        public Aggregator build(String name,
                                ValuesSource valuesSource,
                                boolean showDistribution,
                                DocValueFormat format,
                                SearchContext context,
                                Aggregator parent,
                                List<PipelineAggregator> pipelineAggregators,
                                Map<String, Object> metadata) throws IOException {
            return new StringStatsAggregator(name, showDistribution, (ValuesSource.Bytes) valuesSource,
                format, context, parent, pipelineAggregators, metadata);
        }
    };

    private final boolean showDistribution;

    StringStatsAggregatorFactory(String name, ValuesSourceConfig config,
                                 Boolean showDistribution,
                                 QueryShardContext queryShardContext,
                                 AggregatorFactory parent, AggregatorFactories.Builder subFactoriesBuilder, Map<String, Object> metadata)
                                    throws IOException {
        super(name, config, queryShardContext, parent, subFactoriesBuilder, metadata);
        this.showDistribution = showDistribution;
    }

    @Override
    protected Aggregator createUnmapped(SearchContext searchContext,
                                            Aggregator parent,
                                            List<PipelineAggregator> pipelineAggregators,
                                            Map<String, Object> metadata) throws IOException {
        return new StringStatsAggregator(name, showDistribution,null, config.format(), searchContext, parent,
                                         pipelineAggregators, metadata);
    }

    @Override
    protected Aggregator doCreateInternal(ValuesSource valuesSource,
                                          SearchContext searchContext,
                                          Aggregator parent,
                                          boolean collectsFromSingleBucket,
                                          List<PipelineAggregator> pipelineAggregators,
                                          Map<String, Object> metadata) throws IOException {
        AggregatorSupplier aggregatorSupplier = queryShardContext.getValuesSourceRegistry().getAggregator(config.valueSourceType(),
            StringStatsAggregationBuilder.NAME);

        if (aggregatorSupplier instanceof StringStatsAggregatorSupplier == false) {
            throw new AggregationExecutionException("Registry miss-match - expected StringStatsAggregatorSupplier, found [" +
                aggregatorSupplier.getClass().toString() + "]");
        }
        return ((StringStatsAggregatorSupplier) aggregatorSupplier).build(name, valuesSource, showDistribution, config.format(),
            searchContext, parent, pipelineAggregators, metadata);
    }

}
