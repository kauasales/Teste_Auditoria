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
package org.elasticsearch.search.aggregations.metrics.avg;

import org.apache.lucene.index.LeafReaderContext;
import org.elasticsearch.common.inject.internal.Nullable;
import org.elasticsearch.common.lease.Releasables;
import org.elasticsearch.common.util.DoubleArray;
import org.elasticsearch.common.util.LongArray;
import org.elasticsearch.index.fielddata.SortedNumericDoubleValues;
import org.elasticsearch.search.aggregations.Aggregator;
import org.elasticsearch.search.aggregations.InternalAggregation;
import org.elasticsearch.search.aggregations.metrics.NumericMetricsAggregator;
import org.elasticsearch.search.aggregations.support.AggregationContext;
import org.elasticsearch.search.aggregations.support.ValuesSource;
import org.elasticsearch.search.aggregations.support.ValuesSourceAggregatorFactory;
import org.elasticsearch.search.aggregations.support.ValuesSourceConfig;
import org.elasticsearch.search.aggregations.support.format.ValueFormatter;

import java.io.IOException;
import java.util.Map;

/**
 *
 */
public class AvgAggregator extends NumericMetricsAggregator.SingleValue {

    private final ValuesSource.Numeric valuesSource;
    private SortedNumericDoubleValues values;

    private LongArray counts;
    private DoubleArray sums;
    private ValueFormatter formatter;

    public AvgAggregator(String name, ValuesSource.Numeric valuesSource, @Nullable ValueFormatter formatter,
            AggregationContext context, Aggregator parent, Map<String, Object> metaData) throws IOException {
        super(name,context, parent, metaData);
        this.valuesSource = valuesSource;
        this.formatter = formatter;
        if (valuesSource != null) {
            counts = bigArrays.newLongArray(1, true);
            sums = bigArrays.newDoubleArray(1, true);
        }
    }

    @Override
    public boolean shouldCollect() {
        return valuesSource != null;
    }

    @Override
    public void setNextReader(LeafReaderContext reader) {
        values = valuesSource.doubleValues();
    }

    @Override
    public void collect(int doc, long owningBucketOrdinal) throws IOException {
        counts = bigArrays.grow(counts, owningBucketOrdinal + 1);
        sums = bigArrays.grow(sums, owningBucketOrdinal + 1);

        values.setDocument(doc);
        final int valueCount = values.count();
        counts.increment(owningBucketOrdinal, valueCount);
        double sum = 0;
        for (int i = 0; i < valueCount; i++) {
            sum += values.valueAt(i);
        }
        sums.increment(owningBucketOrdinal, sum);
    }

    @Override
    public double metric(long owningBucketOrd) {
        return valuesSource == null ? Double.NaN : sums.get(owningBucketOrd) / counts.get(owningBucketOrd);
    }

    @Override
    public InternalAggregation buildAggregation(long owningBucketOrdinal) {
        if (valuesSource == null || owningBucketOrdinal >= counts.size()) {
            return new InternalAvg(name, 0l, 0, formatter, metaData());
        }
        return new InternalAvg(name, sums.get(owningBucketOrdinal), counts.get(owningBucketOrdinal), formatter, metaData());
    }

    @Override
    public InternalAggregation buildEmptyAggregation() {
        return new InternalAvg(name, 0.0, 0l, formatter, metaData());
    }

    public static class Factory extends ValuesSourceAggregatorFactory.LeafOnly<ValuesSource.Numeric> {

        public Factory(String name, String type, ValuesSourceConfig<ValuesSource.Numeric> valuesSourceConfig) {
            super(name, type, valuesSourceConfig);
        }

        @Override
        protected Aggregator createUnmapped(AggregationContext aggregationContext, Aggregator parent, Map<String, Object> metaData) throws IOException {
            return new AvgAggregator(name, null, config.formatter(), aggregationContext, parent, metaData);
        }

        @Override
        protected Aggregator doCreateInternal(ValuesSource.Numeric valuesSource, AggregationContext aggregationContext, Aggregator parent, boolean collectsFromSingleBucket, Map<String, Object> metaData) throws IOException {
            return new AvgAggregator(name, valuesSource, config.formatter(), aggregationContext, parent, metaData);
        }
    }

    @Override
    public void doClose() {
        Releasables.close(counts, sums);
    }

}
