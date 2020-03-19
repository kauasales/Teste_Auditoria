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

package org.elasticsearch.client;

import org.apache.http.client.methods.HttpPost;
import org.elasticsearch.client.RequestConverters.Params;
import org.elasticsearch.client.asyncsearch.SubmitAsyncSearchRequest;
import org.elasticsearch.rest.action.search.RestSearchAction;

import java.io.IOException;
import java.util.Locale;

import static org.elasticsearch.client.RequestConverters.REQUEST_BODY_CONTENT_TYPE;

final class AsyncSearchRequestConverters {

    static Request submitAsyncSearch(SubmitAsyncSearchRequest asyncSearchRequest) throws IOException {
        String endpoint = new RequestConverters.EndpointBuilder().addCommaSeparatedPathParts(
                asyncSearchRequest.getIndices())
                .addPathPartAsIs("_async_search").build();
        Request request = new Request(HttpPost.METHOD_NAME, endpoint);
        Params params = new RequestConverters.Params();
        // add all typical search params and search request source as body
        addSearchRequestParams(params, asyncSearchRequest);
        if (asyncSearchRequest.getSearchSource() != null) {
            request.setEntity(RequestConverters.createEntity(asyncSearchRequest.getSearchSource(), REQUEST_BODY_CONTENT_TYPE));
        }
        // set async search submit specific parameters
        if (asyncSearchRequest.isCleanOnCompletion() != null) {
            params.putParam("clean_on_completion", asyncSearchRequest.isCleanOnCompletion().toString());
        }
        if (asyncSearchRequest.getKeepAlive() != null) {
            params.putParam("keep_alive", asyncSearchRequest.getKeepAlive().getStringRep());
        }
        if (asyncSearchRequest.getWaitForCompletion() != null) {
            params.putParam("wait_for_completion", asyncSearchRequest.getWaitForCompletion().getStringRep());
        }
        request.addParameters(params.asMap());
        return request;
    }

    static void addSearchRequestParams(Params params, SubmitAsyncSearchRequest request) {
        params.putParam(RestSearchAction.TYPED_KEYS_PARAM, "true");
        params.withRouting(request.getRouting());
        params.withPreference(request.getPreference());
        params.withIndicesOptions(request.getIndicesOptions());
        params.withSearchType(request.getSearchType().name().toLowerCase(Locale.ROOT));
        params.withMaxConcurrentShardRequests(request.getMaxConcurrentShardRequests());
        if (request.getRequestCache() != null) {
            params.withRequestCache(request.getRequestCache());
        }
        if (request.getAllowPartialSearchResults() != null) {
            params.withPartialResults(request.getAllowPartialSearchResults());
        }
        params.withBatchedReduceSize(request.getBatchedReduceSize());
    }
}
