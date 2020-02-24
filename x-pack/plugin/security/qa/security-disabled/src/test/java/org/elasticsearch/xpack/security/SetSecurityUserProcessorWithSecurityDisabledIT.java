/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security;

import org.apache.http.util.EntityUtils;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.test.rest.ESRestTestCase;
import org.hamcrest.Matchers;

/**
 * Tests that it is possible to <em>define</em> a pipeline with the
 * {@link org.elasticsearch.xpack.security.ingest.SetSecurityUserProcessor} on a cluster with security disabled, but it is not possible
 * to use that pipeline for ingestion.
 */
public class SetSecurityUserProcessorWithSecurityDisabledIT extends ESRestTestCase {

    public void testDefineAndUseProcessor() throws Exception {
        final String pipeline = "pipeline-" + getTestName();
        final String index = "index-" + getTestName();
        {
            final Request putPipeline = new Request("PUT", "/_ingest/pipeline/" + pipeline);
            putPipeline.setJsonEntity("{" +
                " \"description\": \"Test pipeline (" + getTestName() + ")\"," +
                " \"processors\":[{" +
                "  \"set_security_user\":{ \"field\": \"user\" }" +
                " }]" +
                "}");
            final Response response = client().performRequest(putPipeline);
            assertOK(response);
        }

        {
            final Request ingest = new Request("PUT", "/" + index + "/_doc/1?pipeline=" + pipeline);
            ingest.setJsonEntity("{\"field\":\"value\"}");
            final ResponseException ex = expectThrows(ResponseException.class, () -> client().performRequest(ingest));
            final Response response = ex.getResponse();
            assertThat(EntityUtils.toString(response.getEntity()), Matchers.containsString("is security enabled on this cluster"));
        }
    }

}
