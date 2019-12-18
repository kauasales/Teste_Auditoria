/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.dataframe.evaluation.classification;

import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.search.aggregations.Aggregations;
import org.elasticsearch.test.AbstractSerializingTestCase;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.elasticsearch.test.hamcrest.OptionalMatchers.isEmpty;
import static org.elasticsearch.xpack.core.ml.dataframe.evaluation.MockAggregations.mockCardinality;
import static org.elasticsearch.xpack.core.ml.dataframe.evaluation.MockAggregations.mockFilters;
import static org.elasticsearch.xpack.core.ml.dataframe.evaluation.MockAggregations.mockSingleValue;
import static org.elasticsearch.xpack.core.ml.dataframe.evaluation.MockAggregations.mockTerms;
import static org.elasticsearch.xpack.core.ml.dataframe.evaluation.classification.TupleMatchers.isTuple;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;

public class PrecisionTests extends AbstractSerializingTestCase<Precision> {

    @Override
    protected Precision doParseInstance(XContentParser parser) throws IOException {
        return Precision.fromXContent(parser);
    }

    @Override
    protected Precision createTestInstance() {
        return createRandom();
    }

    @Override
    protected Writeable.Reader<Precision> instanceReader() {
        return Precision::new;
    }

    @Override
    protected boolean supportsUnknownFields() {
        return true;
    }

    public static Precision createRandom() {
        Integer size = randomBoolean() ? null : randomIntBetween(1, 1000);
        return new Precision(size);
    }

    public void testConstructor_SizeValidationFailures() {
        {
            ElasticsearchStatusException e = expectThrows(ElasticsearchStatusException.class, () -> new Precision(-1));
            assertThat(e.getMessage(), equalTo("[size] must be an integer in [1, 1000]"));
        }
        {
            ElasticsearchStatusException e = expectThrows(ElasticsearchStatusException.class, () -> new Precision(0));
            assertThat(e.getMessage(), equalTo("[size] must be an integer in [1, 1000]"));
        }
        {
            ElasticsearchStatusException e = expectThrows(ElasticsearchStatusException.class, () -> new Precision(1001));
            assertThat(e.getMessage(), equalTo("[size] must be an integer in [1, 1000]"));
        }
    }

    public void testProcess() {
        Aggregations aggs = new Aggregations(Arrays.asList(
            mockTerms(Precision.ACTUAL_CLASSES_NAMES_AGG_NAME),
            mockFilters(Precision.BY_PREDICTED_CLASS_AGG_NAME),
            mockSingleValue(Precision.AVG_PRECISION_AGG_NAME, 0.8123),
            mockCardinality(Precision.CARDINALITY_OF_ACTUAL_CLASS, 15),
            mockSingleValue("some_other_single_metric_agg", 0.2377)
        ));

        Precision precision = new Precision();
        precision.process(aggs);

        assertThat(precision.aggs("act", "pred"), isTuple(empty(), empty()));
        assertThat(precision.getResult().get(), equalTo(new Precision.Result(List.of(), 0.8123, 5)));
    }

    public void testProcess_GivenMissingAgg() {
        {
            Aggregations aggs = new Aggregations(Arrays.asList(
                mockFilters(Precision.BY_PREDICTED_CLASS_AGG_NAME),
                mockSingleValue("some_other_single_metric_agg", 0.2377)
            ));
            Precision precision = new Precision();
            precision.process(aggs);
            assertThat(precision.getResult(), isEmpty());
        }
        {
            Aggregations aggs = new Aggregations(Arrays.asList(
                mockSingleValue(Precision.AVG_PRECISION_AGG_NAME, 0.8123),
                mockSingleValue("some_other_single_metric_agg", 0.2377)
            ));
            Precision precision = new Precision();
            precision.process(aggs);
            assertThat(precision.getResult(), isEmpty());
        }
    }

    public void testProcess_GivenAggOfWrongType() {
        {
            Aggregations aggs = new Aggregations(Arrays.asList(
                mockFilters(Precision.BY_PREDICTED_CLASS_AGG_NAME),
                mockFilters(Precision.AVG_PRECISION_AGG_NAME)
            ));
            Precision precision = new Precision();
            precision.process(aggs);
            assertThat(precision.getResult(), isEmpty());
        }
        {
            Aggregations aggs = new Aggregations(Arrays.asList(
                mockSingleValue(Precision.BY_PREDICTED_CLASS_AGG_NAME, 1.0),
                mockSingleValue(Precision.AVG_PRECISION_AGG_NAME, 0.8123)
            ));
            Precision precision = new Precision();
            precision.process(aggs);
            assertThat(precision.getResult(), isEmpty());
        }
    }
}
