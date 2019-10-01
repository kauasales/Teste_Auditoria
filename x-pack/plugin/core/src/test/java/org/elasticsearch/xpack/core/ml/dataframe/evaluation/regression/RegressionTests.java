/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.dataframe.evaluation.regression;

import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.test.AbstractSerializingTestCase;
import org.elasticsearch.xpack.core.ml.dataframe.evaluation.MlEvaluationNamedXContentProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;

public class RegressionTests extends AbstractSerializingTestCase<Regression> {

    @Override
    protected NamedWriteableRegistry getNamedWriteableRegistry() {
        return new NamedWriteableRegistry(new MlEvaluationNamedXContentProvider().getNamedWriteables());
    }

    @Override
    protected NamedXContentRegistry xContentRegistry() {
        return new NamedXContentRegistry(new MlEvaluationNamedXContentProvider().getNamedXContentParsers());
    }

    public static Regression createRandom() {
        List<RegressionMetric> metrics = new ArrayList<>();
        if (randomBoolean()) {
            metrics.add(MeanSquaredErrorTests.createRandom());
        }
        if (randomBoolean()) {
            metrics.add(RSquaredTests.createRandom());
        }
        return new Regression(randomAlphaOfLength(10), randomAlphaOfLength(10), metrics.isEmpty() ? null : metrics);
    }

    @Override
    protected Regression doParseInstance(XContentParser parser) throws IOException {
        return Regression.fromXContent(parser);
    }

    @Override
    protected Regression createTestInstance() {
        return createRandom();
    }

    @Override
    protected Writeable.Reader<Regression> instanceReader() {
        return Regression::new;
    }

    public void testConstructor_GivenEmptyMetrics() {
        ElasticsearchStatusException e = expectThrows(ElasticsearchStatusException.class,
            () -> new Regression("foo", "bar", Collections.emptyList()));
        assertThat(e.getMessage(), equalTo("[regression] must have one or more metrics"));
    }

    public void testBuildSearch() {
        QueryBuilder userProvidedQuery =
            QueryBuilders.boolQuery()
                .filter(QueryBuilders.termQuery("field_A", "some-value"))
                .filter(QueryBuilders.termQuery("field_B", "some-other-value"));
        QueryBuilder expectedSearchQuery =
            QueryBuilders.boolQuery()
                .filter(QueryBuilders.existsQuery("act"))
                .filter(QueryBuilders.existsQuery("pred"))
                .filter(QueryBuilders.boolQuery()
                    .filter(QueryBuilders.termQuery("field_A", "some-value"))
                    .filter(QueryBuilders.termQuery("field_B", "some-other-value")));

        Regression evaluation = new Regression("act", "pred", Arrays.asList(new MeanSquaredError()));

        SearchSourceBuilder searchSourceBuilder = evaluation.buildSearch(userProvidedQuery);
        assertThat(searchSourceBuilder.query(), equalTo(expectedSearchQuery));
        assertThat(searchSourceBuilder.aggregations().count(), greaterThan(0));
    }
}
