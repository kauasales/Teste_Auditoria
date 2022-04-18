/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.test.eql;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;

import java.util.List;

import static org.elasticsearch.test.eql.DataLoader.TEST_SAMPLE;

public abstract class EqlSampleTestCase extends BaseEqlSpecTestCase {

    public EqlSampleTestCase(String query, String name, long[] eventIds, String[] joinKeys) {
        this(TEST_SAMPLE, query, name, eventIds, joinKeys);
    }

    public EqlSampleTestCase(String index, String query, String name, long[] eventIds, String[] joinKeys) {
        super(index, query, name, eventIds, joinKeys);
    }

    @ParametersFactory(shuffle = false, argumentFormatting = PARAM_FORMATTING)
    public static List<Object[]> readTestSpecs() throws Exception {
        return asArray(EqlSpecLoader.load("/test_sample.toml"));
    }

    @Override
    protected String tiebreaker() {
        return null;
    }

    @Override
    protected String idField() {
        return "id";
    }
}
