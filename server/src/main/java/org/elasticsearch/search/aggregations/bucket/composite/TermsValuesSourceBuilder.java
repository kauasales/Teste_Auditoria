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

package org.elasticsearch.search.aggregations.bucket.composite;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.script.Script;
import org.elasticsearch.search.DocValueFormat;
import org.elasticsearch.search.aggregations.support.CoreValuesSourceType;
import org.elasticsearch.search.aggregations.support.ValuesSource;
import org.elasticsearch.search.aggregations.support.ValuesSourceConfig;
import org.elasticsearch.search.aggregations.support.ValuesSourceRegistry;
import org.elasticsearch.search.aggregations.support.ValuesSourceType;

import java.io.IOException;
import java.util.List;
import java.util.function.LongConsumer;
import java.util.function.LongUnaryOperator;

/**
 * A {@link CompositeValuesSourceBuilder} that builds a {@link ValuesSource} from a {@link Script} or
 * a field name.
 */
public class TermsValuesSourceBuilder extends CompositeValuesSourceBuilder<TermsValuesSourceBuilder> {
    static final String TYPE = "terms";

    private static final ObjectParser<TermsValuesSourceBuilder, Void> PARSER;
    static {
        PARSER = new ObjectParser<>(TermsValuesSourceBuilder.TYPE);
        CompositeValuesSourceParserHelper.declareValuesSourceFields(PARSER, null);
    }
    static TermsValuesSourceBuilder parse(String name, XContentParser parser) throws IOException {
        return PARSER.parse(parser, new TermsValuesSourceBuilder(name), null);
    }

    public TermsValuesSourceBuilder(String name) {
        super(name);
    }

    protected TermsValuesSourceBuilder(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    protected void innerWriteTo(StreamOutput out) throws IOException {}

    @Override
    protected void doXContentBody(XContentBuilder builder, Params params) throws IOException {}

    @Override
    public String type() {
        return TYPE;
    }

    static void register(ValuesSourceRegistry.Builder builder) {
        builder.registerComposite(
            TYPE,
            List.of(CoreValuesSourceType.DATE, CoreValuesSourceType.NUMERIC, CoreValuesSourceType.BOOLEAN),
            (valuesSourceConfig, compositeBucketStrategy, name, hasScript, format, missingBucket, order) -> {
                final DocValueFormat docValueFormat;
                if (format == null && valuesSourceConfig.valueSourceType() == CoreValuesSourceType.DATE) {
                    // defaults to the raw format on date fields (preserve timestamp as longs).
                    docValueFormat = DocValueFormat.RAW;
                } else {
                    docValueFormat = valuesSourceConfig.format();
                }
                return new CompositeValuesSourceConfig(
                    name,
                    valuesSourceConfig.fieldType(),
                    valuesSourceConfig.getValuesSource(),
                    docValueFormat,
                    order,
                    missingBucket,
                    hasScript,
                    (
                        BigArrays bigArrays,
                        IndexReader reader,
                        int size,
                        LongConsumer addRequestCircuitBreakerBytes,
                        CompositeValuesSourceConfig compositeValuesSourceConfig) -> {

                        final ValuesSource.Numeric vs = (ValuesSource.Numeric) compositeValuesSourceConfig.valuesSource();
                        if (vs.isFloatingPoint()) {
                            return new DoubleValuesSource(
                                bigArrays,
                                compositeValuesSourceConfig.fieldType(),
                                vs::doubleValues,
                                compositeValuesSourceConfig.format(),
                                compositeValuesSourceConfig.missingBucket(),
                                size,
                                compositeValuesSourceConfig.reverseMul()
                            );

                        } else {
                            final LongUnaryOperator rounding;
                            if (vs instanceof RoundingValuesSource) {
                                // TODO: I'm pretty sure we can't get a RoundingValuesSource here.  This was copy/pasta from the old,
                                //       global logic in CompositeValuesSourceConfig, which could have had a rounding values source.
                                //       Now that path should be covered in DateHistogramValuesSourceBuilder
                                rounding = ((RoundingValuesSource) vs)::round;
                            } else {
                                rounding = LongUnaryOperator.identity();
                            }
                            return new LongValuesSource(
                                bigArrays,
                                compositeValuesSourceConfig.fieldType(),
                                vs::longValues,
                                rounding,
                                compositeValuesSourceConfig.format(),
                                compositeValuesSourceConfig.missingBucket(),
                                size,
                                compositeValuesSourceConfig.reverseMul()
                            );
                        }

                    });
                    });


        builder.registerComposite(
            TYPE,
            List.of(CoreValuesSourceType.BYTES, CoreValuesSourceType.IP),
            (valuesSourceConfig, compositeBucketStrategy, name, hasScript, format, missingBucket, order) -> {
                return new CompositeValuesSourceConfig(
                    name,
                    valuesSourceConfig.fieldType(),
                    valuesSourceConfig.getValuesSource(),
                    valuesSourceConfig.format(),
                    order,
                    missingBucket,
                    hasScript,
                    (
                        BigArrays bigArrays,
                        IndexReader reader,
                        int size,
                        LongConsumer addRequestCircuitBreakerBytes,
                        CompositeValuesSourceConfig compositeValuesSourceConfig) -> {

                        if (valuesSourceConfig.hasGlobalOrdinals() && reader instanceof DirectoryReader) {
                            ValuesSource.Bytes.WithOrdinals vs = (ValuesSource.Bytes.WithOrdinals) compositeValuesSourceConfig
                                .valuesSource();
                            return new GlobalOrdinalValuesSource(
                                bigArrays,
                                compositeValuesSourceConfig.fieldType(),
                                vs::globalOrdinalsValues,
                                compositeValuesSourceConfig.format(),
                                compositeValuesSourceConfig.missingBucket(),
                                size,
                                compositeValuesSourceConfig.reverseMul()
                            );
                        } else {
                            ValuesSource.Bytes vs = (ValuesSource.Bytes) compositeValuesSourceConfig.valuesSource();
                            return new BinaryValuesSource(
                                bigArrays,
                                addRequestCircuitBreakerBytes,
                                compositeValuesSourceConfig.fieldType(),
                                vs::bytesValues,
                                compositeValuesSourceConfig.format(),
                                compositeValuesSourceConfig.missingBucket(),
                                size,
                                compositeValuesSourceConfig.reverseMul()
                            );
                        }
                    }
                );

            }
        );
    }

    @Override
    protected ValuesSourceType getDefaultValuesSourceType() {
        return CoreValuesSourceType.BYTES;
    }

    @Override
    protected CompositeValuesSourceConfig innerBuild(QueryShardContext queryShardContext, ValuesSourceConfig config) throws IOException {
        return queryShardContext.getValuesSourceRegistry()
            .getComposite(TYPE, config)
            .apply(config, new CompositeBucketStrategy(), name, script() != null, format(), missingBucket(), order());
    }
}
