/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.inference.preprocessing;

import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.test.AbstractSerializingTestCase;
import org.junit.Before;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.equalTo;

public class TargetMeanEncodingTests extends AbstractSerializingTestCase<TargetMeanEncoding> {

    private boolean lenient;

    @Before
    public void chooseStrictOrLenient() {
        lenient = randomBoolean();
    }

    @Override
    protected TargetMeanEncoding doParseInstance(XContentParser parser) throws IOException {
        return lenient ? TargetMeanEncoding.fromXContentLenient(parser) : TargetMeanEncoding.fromXContentStrict(parser);
    }

    @Override
    protected boolean supportsUnknownFields() {
        return lenient;
    }

    @Override
    protected Predicate<String> getRandomFieldsExcludeFilter() {
        return field -> !field.isEmpty();
    }

    @Override
    protected TargetMeanEncoding createTestInstance() {
        return createRandom();
    }

    public static TargetMeanEncoding createRandom() {
        int valuesSize = randomIntBetween(1, 10);
        Map<String, Double> valueMap = new HashMap<>();
        for (int i = 0; i < valuesSize; i++) {
            valueMap.put(randomAlphaOfLength(10), randomDoubleBetween(0.0, 1.0, false));
        }
        return new TargetMeanEncoding(randomAlphaOfLength(10),
            randomAlphaOfLength(10),
            valueMap,
            randomDoubleBetween(0.0, 1.0, false));
    }

    @Override
    protected Writeable.Reader<TargetMeanEncoding> instanceReader() {
        return TargetMeanEncoding::new;
    }

    public void testProcess() {
        String field = "categorical";
        List<String> values = Arrays.asList("foo", "bar", "foobar", "baz", "farequote");
        Map<String, Double> valueMap = values.stream().collect(Collectors.toMap(Function.identity(),
            v -> randomDoubleBetween(0.0, 1.0, false)));
        String encodedFeatureName = "encoded";
        for(int i = 0; i < NUMBER_OF_TEST_RUNS; i++) {
            Double defaultvalue = randomDouble();
            TargetMeanEncoding encoding = new TargetMeanEncoding(field, encodedFeatureName, valueMap, defaultvalue);
            int numFields = randomIntBetween(1, 5);
            Map<String, Object> fieldValues = new HashMap<>(numFields);
            for (int k = 0; k < numFields; k++) {
                fieldValues.put(randomAlphaOfLength(10), randomAlphaOfLength(10));
            }
            boolean addedField = randomBoolean();
            String addedValue = null;
            if (addedField) {
                addedValue = randomBoolean() ? "unknownValue" : randomFrom(values);
                fieldValues.put(field, addedValue);
            }
            Map<String, Object> resultFields = encoding.process(fieldValues);
            if (addedField) {
                assertThat(resultFields.get(encodedFeatureName), equalTo(valueMap.getOrDefault(addedValue, defaultvalue)));
            }
        }
    }
}
