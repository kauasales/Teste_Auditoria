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

package org.elasticsearch.rest.action.document;

import org.elasticsearch.ResourceNotFoundException;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.rest.FakeRestChannel;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.junit.AfterClass;

import static java.util.Collections.emptyMap;
import static org.elasticsearch.rest.RestStatus.OK;
import static org.elasticsearch.rest.action.document.RestGetSourceAction.RestGetSourceResponseListener;
import static org.hamcrest.Matchers.equalTo;

public class RestGetSourceActionTests extends ESTestCase {

    private static RestRequest request = new FakeRestRequest();
    private static FakeRestChannel channel = new FakeRestChannel(request, true, 0);
    private static RestGetSourceResponseListener listener = new RestGetSourceResponseListener(channel, request);

    @AfterClass
    public static void cleanupReferences() {
        request = null;
        channel = null;
        listener = null;
    }

    public void testRestGetSourceAction() throws Exception {
        // GIVEN a REST Get Source action response with an existing result and a non-null source
        final BytesReference source = new BytesArray("{\"foo\": \"bar\"}");
        final GetResponse getResponse = new GetResponse(new GetResult("index1", "_doc", "1", -1, true, source, emptyMap()));

        // WHEN building the REST response
        final RestResponse restResponse = listener.buildResponse(getResponse);

        // THEN expect to retrieve document source
        assertThat(restResponse.status(), equalTo(OK));
        assertThat(restResponse.contentType(), equalTo("application/json; charset=UTF-8"));
        assertThat(restResponse.content(), equalTo(new BytesArray("{\"foo\": \"bar\"}")));
    }

    public void testRestGetSourceActionWithNullSource() {
        // GIVEN a REST Get Source action response with a non-existing result and a null source
        final GetResponse getResponse = new GetResponse(new GetResult("index1", "_doc", "1", -1, false, null, emptyMap()));

        // WHEN building the REST response
        // THEN expect a resource not found exception
        final ResourceNotFoundException exception = expectThrows(ResourceNotFoundException.class,
            () -> listener.buildResponse(getResponse));

        // THEN expect a formatted error message
        assertThat(exception.getMessage(), equalTo("Document or source not found [index1]/[_doc]/[1]"));
    }
}
