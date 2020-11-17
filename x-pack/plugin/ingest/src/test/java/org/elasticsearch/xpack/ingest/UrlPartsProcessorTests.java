/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.ingest;

import org.elasticsearch.ingest.IngestDocument;
import org.elasticsearch.test.ESTestCase;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.Matchers.containsInAnyOrder;

public class UrlPartsProcessorTests extends ESTestCase {


    public void testUrlParts() throws Exception {

        // simple URL
        testUrlParsing("http://www.google.com",
            Map.of(
                "scheme", "http",
                "domain", "www.google.com",
                "path", ""
            ));

        // custom port
        testUrlParsing("http://www.google.com:88",
            Map.of(
                "scheme", "http",
                "domain", "www.google.com",
                "path", "",
                "port", 88
            ));

        // file
        testUrlParsing("http://www.google.com:88/google.png",
            Map.of(
                "scheme", "http",
                "domain", "www.google.com",
                "extension", "png",
                "path", "/google.png",
                "port", 88
            ));

        // fragment
        testUrlParsing("https://www.google.com:88/foo#bar",
            Map.of(
                "scheme", "https",
                "domain", "www.google.com",
                "fragment", "bar",
                "path", "/foo",
                "port", 88
            ));

        // path, extension
        testUrlParsing("https://www.google.com:88/foo.jpg",
            Map.of(
                "scheme", "https",
                "domain", "www.google.com",
                "path", "/foo.jpg",
                "extension", "jpg",
                "port", 88
            ));

        // query
        testUrlParsing("https://www.google.com:88/foo?key=val",
            Map.of(
                "scheme", "https",
                "domain", "www.google.com",
                "path", "/foo",
                "query", "key=val",
                "port", 88
            ));

        // user_info
        testUrlParsing("https://user:pw@www.google.com:88/foo",
            Map.of(
                "scheme", "https",
                "domain", "www.google.com",
                "path", "/foo",
                "port", 88,
                "user_info", "user:pw",
                "username", "user",
                "password", "pw"
            ));

        // everything!
        testUrlParsing("https://user:pw@testing.google.com:8080/foo/bar?foo1=bar1&foo2=bar2#anchorVal",
            Map.of(
                "scheme", "https",
                "domain", "testing.google.com",
                "fragment", "anchorVal",
                "path", "/foo/bar",
                "port", 8080,
                "username", "user",
                "password", "pw",
                "user_info", "user:pw",
                "query", "foo1=bar1&foo2=bar2"
            ));

        // keep original
        testUrlParsing(true, false, "http://www.google.com:88/foo#bar",
            Map.of(
                "scheme", "http",
                "domain", "www.google.com",
                "fragment", "bar",
                "path", "/foo",
                "port", 88
            ));

        // remove if successful
        testUrlParsing(false, true, "http://www.google.com:88/foo#bar",
            Map.of(
                "scheme", "http",
                "domain", "www.google.com",
                "fragment", "bar",
                "path", "/foo",
                "port", 88
            ));
    }

    private void testUrlParsing(String url, Map<String, Object> expectedValues) throws Exception {
        testUrlParsing(false, false, url, expectedValues);
    }

    private void testUrlParsing(
        boolean keepOriginal,
        boolean removeIfSuccessful,
        String url,
        Map<String, Object> expectedValues) throws Exception {
        UrlPartsProcessor processor = new UrlPartsProcessor(null, null, "field", "url", removeIfSuccessful, keepOriginal);

        Map<String, Object> source = new HashMap<>();
        source.put("field", url);
        IngestDocument input = new IngestDocument(source, Map.of());
        IngestDocument output = processor.execute(input);

        Map<String, Object> expectedSourceAndMetadata = new HashMap<>();

        if (removeIfSuccessful == false) {
            expectedSourceAndMetadata.put("field", url);
        }

        Map<String, Object> values;
        if (keepOriginal) {
            values = new HashMap<>(expectedValues);
            values.put("original", url);
        } else {
            values = expectedValues;
        }
        expectedSourceAndMetadata.put("url", values);

        assertThat(output.getSourceAndMetadata().entrySet(), containsInAnyOrder(expectedSourceAndMetadata.entrySet().toArray()));
    }


}
