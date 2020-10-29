/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

package org.elasticsearch.common.xcontent;

import org.elasticsearch.test.ESTestCase;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;

public class ParsedMediaTypeTests extends ESTestCase {

    MediaTypeRegistry<XContentType> mediaTypeRegistry = new MediaTypeRegistry<XContentType>()
        .register(XContentType.values());

    public void testJsonWithParameters() throws Exception {
        String mediaType = "application/vnd.elasticsearch+json";
        assertThat(ParsedMediaType.parseMediaType(mediaType).getParameters(),
            equalTo(Collections.emptyMap()));
        assertThat(ParsedMediaType.parseMediaType(mediaType + ";").getParameters(),
            equalTo(Collections.emptyMap()));
        assertThat(ParsedMediaType.parseMediaType(mediaType + "; charset=UTF-8").getParameters(),
            equalTo(Map.of("charset", "utf-8")));
        assertThat(ParsedMediaType.parseMediaType(mediaType + "; compatible-with=123;charset=UTF-8").getParameters(),
            equalTo(Map.of("charset", "utf-8", "compatible-with", "123")));
    }

    public void testWhiteSpaceInTypeSubtype() {
        String mediaType = " application/vnd.elasticsearch+json ";
        assertThat(ParsedMediaType.parseMediaType(mediaType).toMediaType(mediaTypeRegistry),
            equalTo(XContentType.JSON));

        assertThat(ParsedMediaType.parseMediaType(mediaType + "; compatible-with=123; charset=UTF-8").getParameters(),
            equalTo(Map.of("charset", "utf-8", "compatible-with", "123")));
        assertThat(ParsedMediaType.parseMediaType(mediaType + "; compatible-with=123;\n charset=UTF-8").getParameters(),
            equalTo(Map.of("charset", "utf-8", "compatible-with", "123")));


    }

//    public void testInvalidParameters() {
//        String mediaType = "application/vnd.elasticsearch+json";
//        assertThat(ParsedMediaType.parseMediaType(mediaType + "; charset=unknown")
//            .toMediaType(mediaTypeRegistry),
//            is(nullValue()));
//        assertThat(ParsedMediaType.parseMediaType(mediaType + "; keyvalueNoEqualsSign")
//                .toMediaType(mediaTypeRegistry),
//            is(nullValue()));
//        assertThat(ParsedMediaType.parseMediaType(mediaType + "; key = value")
//                .toMediaType(mediaTypeRegistry),
//            is(nullValue()));
//        assertThat(ParsedMediaType.parseMediaType(mediaType + "; key=")
//                .toMediaType(mediaTypeRegistry),
//            is(nullValue()));
//    }

    public void testXContentTypes() {
        for (XContentType xContentType : XContentType.values()) {
            ParsedMediaType parsedMediaType = ParsedMediaType.parseMediaType(xContentType.mediaTypeWithoutParameters());
            assertEquals(xContentType.mediaTypeWithoutParameters(), parsedMediaType.mimeTypeWithoutParams());
        }
    }

    public void testWithParameters() {
        String mediaType = "application/foo";
        assertEquals(Collections.emptyMap(), ParsedMediaType.parseMediaType(mediaType).getParameters());
        assertEquals(Collections.emptyMap(), ParsedMediaType.parseMediaType(mediaType + ";").getParameters());
        assertEquals(Map.of("charset", "utf-8"), ParsedMediaType.parseMediaType(mediaType + "; charset=UTF-8").getParameters());
        assertEquals(Map.of("charset", "utf-8", "compatible-with", "123"),
            ParsedMediaType.parseMediaType(mediaType + "; compatible-with=123;charset=UTF-8").getParameters());
    }

    public void testWhiteSpaces() {
        //be lenient with white space since it can be really hard to troubleshoot
        String mediaType = "  application/foo  ";
        ParsedMediaType parsedMediaType = ParsedMediaType.parseMediaType(mediaType + "    ;  compatible-with =  123  ;  charset=UTF-8");
        assertEquals("application/foo", parsedMediaType.mimeTypeWithoutParams());
        assertEquals((Map.of("charset", "utf-8", "compatible-with", "123")), parsedMediaType.getParameters());
    }

    public void testEmptyParams() {
        String mediaType = "application/foo";
        ParsedMediaType parsedMediaType = ParsedMediaType.parseMediaType(mediaType + randomFrom("", " ", ";", ";;", ";;;"));
        assertEquals("application/foo", parsedMediaType.mimeTypeWithoutParams());
        assertEquals(Collections.emptyMap(), parsedMediaType.getParameters());
    }

    public void testMalformedParameters() {
        String mediaType = "application/foo";
        IllegalArgumentException exception = expectThrows(IllegalArgumentException.class,
            () -> ParsedMediaType.parseMediaType(mediaType + "; charsetunknown"));
        assertThat(exception.getMessage(), equalTo("invalid parameters for header [application/foo; charsetunknown]"));

        exception = expectThrows(IllegalArgumentException.class,
            () -> ParsedMediaType.parseMediaType(mediaType + "; char=set=unknown"));
        assertThat(exception.getMessage(), equalTo("invalid parameters for header [application/foo; char=set=unknown]"));
    }

//    public void testMultipleValues() {
//        String mediaType = "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2";
//        ParsedMediaType.parseMediaType(mediaType);
//    }
}
