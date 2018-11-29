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
package org.elasticsearch.common.unit;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.sameInstance;

public class FuzzinessTests extends ESTestCase {

    public void testFromString() {
        assertSame(Fuzziness.AUTO, Fuzziness.fromString("AUTO"));
        assertSame(Fuzziness.AUTO, Fuzziness.fromString("auto"));
        assertSame(Fuzziness.ZERO, Fuzziness.fromString("0"));
        assertSame(Fuzziness.ZERO, Fuzziness.fromString("0.0"));
        assertSame(Fuzziness.ONE, Fuzziness.fromString("1"));
        assertSame(Fuzziness.ONE, Fuzziness.fromString("1.0"));
        assertSame(Fuzziness.TWO, Fuzziness.fromString("2"));
        assertSame(Fuzziness.TWO, Fuzziness.fromString("2.0"));

        // cases that should throw exceptions
        IllegalArgumentException ex = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromString(null));
        assertEquals("fuzziness cannot be null or empty.", ex.getMessage());
        ex = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromString(""));
        assertEquals("fuzziness cannot be null or empty.", ex.getMessage());
        ex = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromString("foo"));
        assertEquals("fuzziness cannot be [foo].", ex.getMessage());
        ex = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromString("1.2"));
        assertEquals("fuzziness needs to be one of 0.0, 1.0 or 2.0 but was 1.2", ex.getMessage());
    }

    public void testNumericConstants() {
        assertSame(Fuzziness.ZERO, Fuzziness.fromEdits(0));
        assertSame(Fuzziness.ZERO, Fuzziness.fromString("0"));
        assertSame(Fuzziness.ZERO, Fuzziness.fromString("0.0"));
        assertThat(Fuzziness.ZERO.asString(), equalTo("0"));
        assertThat(Fuzziness.ZERO.asDistance(), equalTo(0));
        assertThat(Fuzziness.ZERO.asDistance(randomAlphaOfLengthBetween(0, randomIntBetween(1, 500))), equalTo(0));
        assertThat(Fuzziness.ZERO.asFloat(), equalTo(0.0f));

        assertSame(Fuzziness.ONE, Fuzziness.fromEdits(1));
        assertSame(Fuzziness.ONE, Fuzziness.fromString("1"));
        assertSame(Fuzziness.ONE, Fuzziness.fromString("1.0"));
        assertThat(Fuzziness.ONE.asString(), equalTo("1"));
        assertThat(Fuzziness.ONE.asDistance(), equalTo(1));
        assertThat(Fuzziness.ONE.asDistance(randomAlphaOfLengthBetween(0, randomIntBetween(1, 500))), equalTo(1));
        assertThat(Fuzziness.ONE.asFloat(), equalTo(1.0f));

        assertSame(Fuzziness.TWO, Fuzziness.fromEdits(2));
        assertSame(Fuzziness.TWO, Fuzziness.fromString("2"));
        assertSame(Fuzziness.TWO, Fuzziness.fromString("2.0"));
        assertThat(Fuzziness.TWO.asString(), equalTo("2"));
        assertThat(Fuzziness.TWO.asDistance(), equalTo(2));
        assertThat(Fuzziness.TWO.asDistance(randomAlphaOfLengthBetween(0, randomIntBetween(1, 500))), equalTo(2));
        assertThat(Fuzziness.TWO.asFloat(), equalTo(2.0f));
    }

    public void testAutoFuzziness() {
        assertSame(Fuzziness.AUTO, Fuzziness.fromString("auto"));
        assertSame(Fuzziness.AUTO, Fuzziness.fromString("AUTO"));
        assertThat(Fuzziness.AUTO.asString(), equalTo("AUTO"));
        assertThat(Fuzziness.AUTO.asDistance(), equalTo(1));
        assertThat(Fuzziness.AUTO.asDistance(randomAlphaOfLengthBetween(0, 2)), equalTo(0));
        assertThat(Fuzziness.AUTO.asDistance(randomAlphaOfLengthBetween(3, 5)), equalTo(1));
        assertThat(Fuzziness.AUTO.asDistance(randomAlphaOfLengthBetween(6, 100)), equalTo(2));
        assertThat(Fuzziness.AUTO.asFloat(), equalTo(1.0f));
    }

    public void testCustomAutoFuzziness() {
        int lowDistance = randomIntBetween(1, 10);
        int highDistance = randomIntBetween(lowDistance, 20);
        String auto = randomFrom("auto", "AUTO");
        Fuzziness fuzziness = Fuzziness.fromString(auto + ":" + lowDistance + "," + highDistance);
        assertNotSame(Fuzziness.AUTO, fuzziness);
        if (lowDistance != Fuzziness.DEFAULT_LOW_DISTANCE || highDistance != Fuzziness.DEFAULT_HIGH_DISTANCE) {
            assertThat(fuzziness.asString(), equalTo("AUTO:" + lowDistance + "," + highDistance));
        }
        if (lowDistance > 5) {
            assertThat(fuzziness.asDistance(), equalTo(0));
        } else if (highDistance > 5) {
            assertThat(fuzziness.asDistance(), equalTo(1));
        } else {
            assertThat(fuzziness.asDistance(), equalTo(2));
        }
        assertThat(fuzziness.asDistance(randomAlphaOfLengthBetween(0, lowDistance - 1)), equalTo(0));
        if (lowDistance != highDistance) {
            assertThat(fuzziness.asDistance(randomAlphaOfLengthBetween(lowDistance, highDistance - 1)), equalTo(1));
        }
        assertThat(fuzziness.asDistance(randomAlphaOfLengthBetween(highDistance, 100)), equalTo(2));
        assertThat(fuzziness.asFloat(), equalTo(1.0f));
    }

    public void testFromEditsIllegalArgs() {
        int illegalValue = randomValueOtherThanMany(i -> i >= 0 && i <= 2, () -> randomInt());
        IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromEdits(illegalValue));
        assertThat(e.getMessage(), equalTo("Valid edit distances are [0, 1, 2] but was [" + illegalValue + "]"));
    }

    public void testFromStringIllegalArgs() {
        Exception e = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromString(null));
        assertThat(e.getMessage(), equalTo("fuzziness cannot be null or empty."));

        e = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromString(""));
        assertThat(e.getMessage(), equalTo("fuzziness cannot be null or empty."));

        e = expectThrows(IllegalArgumentException.class, () -> Fuzziness.fromString("illegal"));
        assertThat(e.getMessage(), equalTo("fuzziness cannot be [illegal]."));

        e = expectThrows(ElasticsearchParseException.class, () -> Fuzziness.fromString("AUTO:badFormat"));
        assertThat(e.getMessage(), equalTo("failed to find low and high distance values"));
    }

    public void testParseFromXContent() throws IOException {
        final int iters = randomIntBetween(10, 50);
        for (int i = 0; i < iters; i++) {
            {
                float floatValue = randomFrom(0.0f, 1.0f, 2.0f);
                XContentBuilder json = jsonBuilder().startObject()
                        .field(Fuzziness.X_FIELD_NAME, randomBoolean() ? String.valueOf(floatValue) : floatValue)
                        .endObject();
                try (XContentParser parser = createParser(json)) {
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.START_OBJECT));
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.FIELD_NAME));
                    assertThat(parser.nextToken(),
                            anyOf(equalTo(XContentParser.Token.VALUE_NUMBER), equalTo(XContentParser.Token.VALUE_STRING)));
                    Fuzziness fuzziness = Fuzziness.parse(parser);
                    assertThat(fuzziness.asFloat(), equalTo(floatValue));
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.END_OBJECT));
                }
            }
            {
                int intValue = randomIntBetween(0, 2);
                XContentBuilder json = jsonBuilder().startObject()
                        .field(Fuzziness.X_FIELD_NAME, randomBoolean() ? String.valueOf(intValue) : intValue)
                        .endObject();
                try (XContentParser parser = createParser(json)) {
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.START_OBJECT));
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.FIELD_NAME));
                    assertThat(parser.nextToken(), anyOf(equalTo(XContentParser.Token.VALUE_NUMBER),
                        equalTo(XContentParser.Token.VALUE_STRING)));
                    Fuzziness fuzziness = Fuzziness.parse(parser);
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.END_OBJECT));
                    switch (intValue) {
                    case 1:
                        assertThat(fuzziness, sameInstance(Fuzziness.ONE));
                        break;
                    case 2:
                        assertThat(fuzziness, sameInstance(Fuzziness.TWO));
                        break;
                    case 0:
                        assertThat(fuzziness, sameInstance(Fuzziness.ZERO));
                        break;
                    default:
                        break;
                    }
                }
            }
            {
                XContentBuilder json;
                boolean isDefaultAutoFuzzinessTested = randomBoolean();
                Fuzziness expectedFuzziness = Fuzziness.AUTO;
                if (isDefaultAutoFuzzinessTested) {
                    json = Fuzziness.AUTO.toXContent(jsonBuilder().startObject(), null).endObject();
                } else {
                    StringBuilder auto = new StringBuilder();
                    auto = randomBoolean() ? auto.append("AUTO") : auto.append("auto");
                    if (randomBoolean()) {
                        int lowDistance = randomIntBetween(1, 3);
                        int highDistance = randomIntBetween(4, 10);
                        auto.append(":").append(lowDistance).append(",").append(highDistance);
                        expectedFuzziness = Fuzziness.fromString(auto.toString());
                    }
                    json = expectedFuzziness.toXContent(jsonBuilder().startObject(), null).endObject();
                }
                try (XContentParser parser = createParser(json)) {
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.START_OBJECT));
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.FIELD_NAME));
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.VALUE_STRING));
                    Fuzziness fuzziness = Fuzziness.parse(parser);
                    if (isDefaultAutoFuzzinessTested) {
                        assertThat(fuzziness, sameInstance(expectedFuzziness));
                    } else {
                        assertEquals(expectedFuzziness, fuzziness);
                    }
                    assertThat(parser.nextToken(), equalTo(XContentParser.Token.END_OBJECT));
                }
            }
        }
    }

    public void testSerialization() throws IOException {
        Fuzziness fuzziness = Fuzziness.AUTO;
        Fuzziness deserializedFuzziness = doSerializeRoundtrip(fuzziness);
        assertEquals(fuzziness, deserializedFuzziness);

        fuzziness = Fuzziness.fromEdits(randomIntBetween(0, 2));
        deserializedFuzziness = doSerializeRoundtrip(fuzziness);
        assertEquals(fuzziness, deserializedFuzziness);

        // custom AUTO
        int lowDistance = randomIntBetween(1, 10);
        int highDistance = randomIntBetween(lowDistance, 20);
        fuzziness = Fuzziness.fromString("AUTO:" + lowDistance + "," + highDistance);

        deserializedFuzziness = doSerializeRoundtrip(fuzziness);
        assertNotSame(fuzziness, deserializedFuzziness);
        assertEquals(fuzziness, deserializedFuzziness);
        assertEquals(fuzziness.asString(), deserializedFuzziness.asString());
    }

    private static Fuzziness doSerializeRoundtrip(Fuzziness in) throws IOException {
        BytesStreamOutput output = new BytesStreamOutput();
        in.writeTo(output);
        StreamInput streamInput = output.bytes().streamInput();
        return new Fuzziness(streamInput);
    }
}
