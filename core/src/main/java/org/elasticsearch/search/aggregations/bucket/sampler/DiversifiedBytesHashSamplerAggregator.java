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

package org.elasticsearch.search.aggregations.bucket.sampler;

import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.search.DiversifiedTopDocsCollector;
import org.apache.lucene.search.DiversifiedTopDocsCollector.ScoreDocKey;
import org.apache.lucene.search.TopDocsCollector;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.index.fielddata.SortedBinaryDocValues;
import org.elasticsearch.search.aggregations.Aggregator;
import org.elasticsearch.search.aggregations.AggregatorFactories;
import org.elasticsearch.search.aggregations.bucket.BestDocsDeferringCollector;
import org.elasticsearch.search.aggregations.bucket.DeferringBucketCollector;
import org.elasticsearch.search.aggregations.pipeline.PipelineAggregator;
import org.elasticsearch.search.aggregations.support.AggregationContext;
import org.elasticsearch.search.aggregations.support.ValuesSource;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Alternative, faster implementation for converting String keys to longs but
 * with the potential for hash collisions.
 */
public class DiversifiedBytesHashSamplerAggregator extends SamplerAggregator {

    private ValuesSource valuesSource;
    private int maxDocsPerValue;

    public DiversifiedBytesHashSamplerAggregator(String name, int shardSize, AggregatorFactories factories,
            AggregationContext aggregationContext, Aggregator parent, List<PipelineAggregator> pipelineAggregators, Map<String, Object> metaData,
            ValuesSource valuesSource,
            int maxDocsPerValue) throws IOException {
        super(name, shardSize, factories, aggregationContext, parent, pipelineAggregators, metaData);
        this.valuesSource = valuesSource;
        this.maxDocsPerValue = maxDocsPerValue;
    }

    @Override
    public DeferringBucketCollector getDeferringCollector() {
        bdd = new DiverseDocsDeferringCollector();
        return bdd;
    }

    /**
     * A {@link DeferringBucketCollector} that identifies top scoring documents
     * but de-duped by a key then passes only these on to nested collectors.
     * This implementation is only for use with a single bucket aggregation.
     */
    class DiverseDocsDeferringCollector extends BestDocsDeferringCollector {

        DiverseDocsDeferringCollector() {
            super(shardSize, context.bigArrays());
        }


        @Override
        protected TopDocsCollector<ScoreDocKey> createTopDocsCollector(int size) {
            return new ValuesDiversifiedTopDocsCollector(size, maxDocsPerValue);
        }

        // This class extends the DiversifiedTopDocsCollector and provides
        // a lookup from elasticsearch's ValuesSource
        class ValuesDiversifiedTopDocsCollector extends DiversifiedTopDocsCollector {

            private SortedBinaryDocValues values;

            ValuesDiversifiedTopDocsCollector(int numHits, int maxHitsPerValue) {
                super(numHits, maxHitsPerValue);

            }

            @Override
            protected NumericDocValues getKeys(LeafReaderContext context) {
                try {
                    values = valuesSource.bytesValues(context);
                } catch (IOException e) {
                    throw new ElasticsearchException("Error reading values", e);
                }
                return new NumericDocValues() {
                    @Override
                    public long get(int doc) {

                        values.setDocument(doc);
                        final int valuesCount = values.count();
                        if (valuesCount > 1) {
                            throw new IllegalArgumentException("Sample diversifying key must be a single valued-field");
                        }
                        if (valuesCount == 1) {
                            final BytesRef bytes = values.valueAt(0);
                            return bytes.hashCode();
                        }
                        return 0;
                    }
                };
            }

        }

    }

}
