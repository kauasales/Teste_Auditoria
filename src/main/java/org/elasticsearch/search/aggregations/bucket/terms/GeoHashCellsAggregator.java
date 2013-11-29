/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.search.aggregations.bucket.terms;

import org.elasticsearch.index.fielddata.LongValues;
import org.elasticsearch.search.aggregations.Aggregator;
import org.elasticsearch.search.aggregations.AggregatorFactories;
import org.elasticsearch.search.aggregations.InternalAggregations;
import org.elasticsearch.search.aggregations.bucket.BucketsAggregator;
import org.elasticsearch.search.aggregations.bucket.LongHash;
import org.elasticsearch.search.aggregations.bucket.terms.support.BucketPriorityQueue;
import org.elasticsearch.search.aggregations.support.AggregationContext;
import org.elasticsearch.search.aggregations.support.numeric.NumericValuesSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

/**
 * Aggregates data expressed as GeoHash longs (for efficiency's sake) but formats results as Geohash strings.
 * 
 * Basically a copy of LongTermsAggregator.java but changes the final output format to convert longs back
 * into a GeoHash. At some stage, if LongTermsAggregatir is changed to allow alternative bucket formatting options
 * this code could be made redundant.
 */

public class GeoHashCellsAggregator extends BucketsAggregator {

    private static final int INITIAL_CAPACITY = 50; // TODO sizing

    private final InternalOrder order;
    private final int requiredSize;
    private final int shardSize;
    private final NumericValuesSource valuesSource;
    private final LongHash bucketOrds;

    public GeoHashCellsAggregator(String name, AggregatorFactories factories, NumericValuesSource valuesSource,
                               InternalOrder order, int requiredSize, int shardSize, AggregationContext aggregationContext, Aggregator parent) {
        super(name, BucketAggregationMode.PER_BUCKET, factories, INITIAL_CAPACITY, aggregationContext, parent);
        this.valuesSource = valuesSource;
        this.order = order;
        this.requiredSize = requiredSize;
        this.shardSize = shardSize;
        bucketOrds = new LongHash(INITIAL_CAPACITY);
    }

    @Override
    public boolean shouldCollect() {
        return true;
    }

    @Override
    public void collect(int doc, long owningBucketOrdinal) throws IOException {
        assert owningBucketOrdinal == 0;
        final LongValues values = valuesSource.longValues();
        final int valuesCount = values.setDocument(doc);

        for (int i = 0; i < valuesCount; ++i) {
            final long val = values.nextValue();
            long bucketOrdinal = bucketOrds.add(val);
            if (bucketOrdinal < 0) { // already seen
                bucketOrdinal = - 1 - bucketOrdinal;
            }
            collectBucket(doc, bucketOrdinal);
        }
    }

    // private impl that stores a bucket ord. This allows for computing the aggregations lazily.
    static class OrdinalBucket extends GeoHashCells.Bucket {

        long bucketOrd;

        public OrdinalBucket() {
            super(0, 0, (InternalAggregations) null);
        }

    }

    @Override
    public GeoHashCells buildAggregation(long owningBucketOrdinal) {
        assert owningBucketOrdinal == 0;
        final int size = (int) Math.min(bucketOrds.size(), shardSize);

        BucketPriorityQueue ordered = new BucketPriorityQueue(size, order.comparator());
        OrdinalBucket spare = null;
        for (long i = 0; i < bucketOrds.capacity(); ++i) {
            final long ord = bucketOrds.id(i);
            if (ord < 0) {
                // slot is not allocated
                continue;
            }

            if (spare == null) {
                spare = new OrdinalBucket();
            }
            spare.term = bucketOrds.key(i);
            spare.docCount = bucketDocCount(ord);
            spare.bucketOrd = ord;
            spare = (OrdinalBucket) ordered.insertWithOverflow(spare);
        }

        final InternalTerms.Bucket[] list = new InternalTerms.Bucket[ordered.size()];
        for (int i = ordered.size() - 1; i >= 0; --i) {
            final OrdinalBucket bucket = (OrdinalBucket) ordered.pop();
            bucket.aggregations = bucketAggregations(bucket.bucketOrd);
            list[i] = bucket;
        }
        return new GeoHashCells(name, order, requiredSize, Arrays.asList(list));
    }

    @Override
    public GeoHashCells buildEmptyAggregation() {
        return new GeoHashCells(name, order, requiredSize, Collections.<InternalTerms.Bucket>emptyList());
    }
    
    
    public static class Unmapped extends Aggregator {
        private InternalOrder order;
        private int requiredSize;
        public Unmapped(String name, InternalOrder order, int requiredSize, AggregationContext aggregationContext, Aggregator parent) {
            
            super(name, BucketAggregationMode.PER_BUCKET, AggregatorFactories.EMPTY, 0, aggregationContext, parent);
            this.order = order;
            this.requiredSize=requiredSize;
        }

        @Override
        public boolean shouldCollect() {
            return false;
        }

        @Override
        public void collect(int doc, long owningBucketOrdinal) throws IOException {
        }

        @Override
        public GeoHashCells buildAggregation(long owningBucketOrdinal) {
            return (GeoHashCells) buildEmptyAggregation();
        }

        @Override
        public GeoHashCells buildEmptyAggregation() {
            return new GeoHashCells(name,order,requiredSize, Collections.<InternalTerms.Bucket>emptyList());
        }
    }    

}
