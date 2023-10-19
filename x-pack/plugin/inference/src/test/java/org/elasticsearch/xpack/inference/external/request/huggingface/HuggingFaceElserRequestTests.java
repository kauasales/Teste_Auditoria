/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.inference.external.request.huggingface;

import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.HttpPost;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.inference.external.entity.Parser;
import org.elasticsearch.xpack.inference.external.huggingface.HuggingFaceAccount;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

public class HuggingFaceElserRequestTests extends ESTestCase {
    public void testCreateRequest() throws URISyntaxException, IOException {
        var account = new HuggingFaceAccount(new URI("www.google.com"), new SecureString("secret".toCharArray()));
        var entity = new HuggingFaceElserRequestEntity("abc");

        var huggingFaceRequest = new HuggingFaceElserRequest(account, entity);
        var httpRequest = huggingFaceRequest.createRequest();
        httpRequest.getAllHeaders();

        assertThat(httpRequest, instanceOf(HttpPost.class));
        var httpPost = (HttpPost) httpRequest;

        assertThat(httpPost.getURI().toString(), is("www.google.com"));
        assertThat(httpPost.getLastHeader(HttpHeaders.CONTENT_TYPE).getValue(), is(XContentType.JSON.mediaTypeWithoutParameters()));
        assertThat(httpPost.getLastHeader(HttpHeaders.AUTHORIZATION).getValue(), is("Bearer secret"));

        String jsonOutput = Parser.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(Parser.OBJECT_MAPPER.readTree(httpPost.getEntity().getContent()));
        assertThat(jsonOutput, is("""
            {
              "inputs" : "abc"
            }"""));
    }
}
