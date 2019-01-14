/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ml.job.results;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.Writeable.Reader;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.test.AbstractSerializingTestCase;
import org.elasticsearch.xpack.core.ml.job.results.ModelPlot;

import java.io.IOException;
import java.util.Date;
import java.util.Objects;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

public class ModelPlotTests extends AbstractSerializingTestCase<ModelPlot> {

    @Override
    protected ModelPlot createTestInstance() {
        return createTestInstance("foo");
    }

    public ModelPlot createTestInstance(String jobId) {
        ModelPlot modelPlot =
                new ModelPlot(jobId, new Date(randomLongBetween(0, 3000000000000L)), randomNonNegativeLong(), randomInt());
        if (randomBoolean()) {
            modelPlot.setByFieldName(randomAlphaOfLengthBetween(1, 20));
        }
        if (randomBoolean()) {
            modelPlot.setByFieldValue(randomAlphaOfLengthBetween(1, 20));
        }
        if (randomBoolean()) {
            modelPlot.setPartitionFieldName(randomAlphaOfLengthBetween(1, 20));
        }
        if (randomBoolean()) {
            modelPlot.setPartitionFieldValue(randomAlphaOfLengthBetween(1, 20));
        }
        if (randomBoolean()) {
            modelPlot.setModelFeature(randomAlphaOfLengthBetween(1, 20));
        }
        if (randomBoolean()) {
            modelPlot.setModelLower(randomDouble());
        }
        if (randomBoolean()) {
            modelPlot.setModelUpper(randomDouble());
        }
        if (randomBoolean()) {
            modelPlot.setModelMedian(randomDouble());
        }
        if (randomBoolean()) {
            modelPlot.setActual(randomDouble());
        }
        return modelPlot;
    }

    @Override
    protected Reader<ModelPlot> instanceReader() {
        return ModelPlot::new;
    }

    @Override
    protected ModelPlot doParseInstance(XContentParser parser) {
        return ModelPlot.STRICT_PARSER.apply(parser, null);
    }

    public void testEquals_GivenSameObject() {
        ModelPlot modelPlot =
                new ModelPlot(randomAlphaOfLength(15),
                    new Date(randomLongBetween(0, 3000000000000L)), randomNonNegativeLong(), randomInt());

        assertTrue(modelPlot.equals(modelPlot));
    }

    public void testEquals_GivenObjectOfDifferentClass() {
        ModelPlot modelPlot =
                new ModelPlot(randomAlphaOfLength(15),
                    new Date(randomLongBetween(0, 3000000000000L)), randomNonNegativeLong(), randomInt());

        assertFalse(modelPlot.equals("a string"));
    }

    public void testEquals_GivenDifferentPartitionFieldName() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setPartitionFieldName("another");

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentPartitionFieldValue() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setPartitionFieldValue("another");

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentByFieldName() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setByFieldName("another");

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentByFieldValue() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setByFieldValue("another");

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentOverFieldName() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setOverFieldName("another");

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentOverFieldValue() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setOverFieldValue("another");

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentModelFeature() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setModelFeature("another");

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentModelLower() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setModelLower(-1.0);

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentModelUpper() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setModelUpper(-1.0);

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentModelMean() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setModelMedian(-1.0);

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentActual() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setActual(-1.0);

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenDifferentOneNullActual() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();
        modelPlot2.setActual(null);

        assertFalse(modelPlot1.equals(modelPlot2));
        assertFalse(modelPlot2.equals(modelPlot1));
    }

    public void testEquals_GivenEqualmodelPlots() {
        ModelPlot modelPlot1 = createFullyPopulated();
        ModelPlot modelPlot2 = createFullyPopulated();

        assertTrue(modelPlot1.equals(modelPlot2));
        assertTrue(modelPlot2.equals(modelPlot1));
        assertEquals(modelPlot1.hashCode(), modelPlot2.hashCode());
    }

    public void testToXContent_GivenNullActual() throws IOException {
        XContentBuilder builder = JsonXContent.contentBuilder();

        ModelPlot modelPlot = createFullyPopulated();
        modelPlot.setActual(null);
        modelPlot.toXContent(builder, ToXContent.EMPTY_PARAMS);

        String json = Strings.toString(builder);
        assertThat(json, not(containsString("actual")));
    }

    public void testId() {
        ModelPlot plot = new ModelPlot("job-foo", new Date(100L), 60L, 33);
        String byFieldValue = null;
        String overFieldValue = null;
        String partitionFieldValue = null;

        int valuesHash = Objects.hash(byFieldValue, overFieldValue, partitionFieldValue);
        assertEquals("job-foo_model_plot_100_60_33_" + valuesHash + "_0", plot.getId());

        int length = 0;
        if (randomBoolean()) {
            byFieldValue = randomAlphaOfLength(10);
            length += byFieldValue.length();
            plot.setByFieldValue(byFieldValue);
        }
        if (randomBoolean()) {
            overFieldValue = randomAlphaOfLength(10);
            length += overFieldValue.length();
            plot.setOverFieldValue(overFieldValue);
        }
        if (randomBoolean()) {
            partitionFieldValue = randomAlphaOfLength(10);
            length += partitionFieldValue.length();
            plot.setPartitionFieldValue(partitionFieldValue);
        }

        valuesHash = Objects.hash(byFieldValue, overFieldValue, partitionFieldValue);
        assertEquals("job-foo_model_plot_100_60_33_" + valuesHash + "_" + length, plot.getId());
    }

    public void testStrictParser() throws IOException {
        String json = "{\"job_id\":\"job_1\", \"timestamp\":12354667, \"bucket_span\": 3600, \"detector_index\":3, \"foo\":\"bar\"}";
        try (XContentParser parser = createParser(JsonXContent.jsonXContent, json)) {
            IllegalArgumentException e = expectThrows(IllegalArgumentException.class,
                    () -> ModelPlot.STRICT_PARSER.apply(parser, null));

            assertThat(e.getMessage(), containsString("unknown field [foo]"));
        }
    }

    public void testLenientParser() throws IOException {
        String json = "{\"job_id\":\"job_1\", \"timestamp\":12354667, \"bucket_span\": 3600, \"detector_index\":3, \"foo\":\"bar\"}";
        try (XContentParser parser = createParser(JsonXContent.jsonXContent, json)) {
            ModelPlot.LENIENT_PARSER.apply(parser, null);
        }
    }

    private ModelPlot createFullyPopulated() {
        ModelPlot modelPlot = new ModelPlot("foo", new Date(12345678L), 360L, 22);
        modelPlot.setByFieldName("by");
        modelPlot.setByFieldValue("by_val");
        modelPlot.setPartitionFieldName("part");
        modelPlot.setPartitionFieldValue("part_val");
        modelPlot.setModelFeature("sum");
        modelPlot.setModelLower(7.9);
        modelPlot.setModelUpper(34.5);
        modelPlot.setModelMedian(12.7);
        modelPlot.setActual(100.0);
        return modelPlot;
    }
}
