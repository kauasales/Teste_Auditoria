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
package org.elasticsearch.common.geo;

import org.elasticsearch.common.CheckedConsumer;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

public class GeoUtilTests extends ESTestCase {

    public void testPrecisionParser() throws IOException {
        assertEquals(10, parsePrecision(builder -> builder.field("test", 10)));
        assertEquals(10, parsePrecision(builder -> builder.field("test", 10.2)));
        assertEquals(6, parsePrecision(builder -> builder.field("test", "6")));
        assertEquals(7, parsePrecision(builder -> builder.field("test", "1km")));
        assertEquals(7, parsePrecision(builder -> builder.field("test", "1.1km")));
    }

    public void testIncorrectPrecisionParser() {
        expectThrows(NumberFormatException.class, () -> parsePrecision(builder -> builder.field("test", "10.1.1.1")));
        expectThrows(NumberFormatException.class, () -> parsePrecision(builder -> builder.field("test", "364.4smoots")));
        assertEquals(
            "precision too high [0.01mm]",
            expectThrows(IllegalArgumentException.class, () -> parsePrecision(builder -> builder.field("test", "0.01mm"))).getMessage()
        );
    }

    private int parsePrecision(CheckedConsumer<XContentBuilder, IOException> tokenGenerator) throws IOException {
        XContentBuilder builder = jsonBuilder().startObject();
        tokenGenerator.accept(builder);
        builder.endObject();
        XContentParser parser = createParser(JsonXContent.jsonXContent, BytesReference.bytes(builder));
        parser.nextToken(); // {
        parser.nextToken(); // field name
        parser.nextToken(); // field value
        return GeoUtils.parsePrecision(parser);
    }
}
