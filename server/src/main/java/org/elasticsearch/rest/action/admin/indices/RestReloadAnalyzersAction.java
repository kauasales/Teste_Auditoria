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

package org.elasticsearch.rest.action.admin.indices;

import org.elasticsearch.action.admin.indices.reloadanalyzer.ReloadAnalyzersRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;

import java.io.IOException;

import static org.elasticsearch.client.Requests.reloadAnalyzersRequest;
public class RestReloadAnalyzersAction extends BaseRestHandler {

    public RestReloadAnalyzersAction(Settings settings, RestController controller) {
        super(settings);
        controller.registerHandler(RestRequest.Method.GET, "/{index}/_reload_search_analyzers", this);
        controller.registerHandler(RestRequest.Method.POST, "/{index}/_reload_search_analyzers", this);
    }

    @Override
    public String getName() {
        return "reload_search_analyzers_action";
    }

    @Override
    public RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        ReloadAnalyzersRequest reloadAnalyzersRequest = reloadAnalyzersRequest(Strings.splitStringByCommaToArray(request.param("index")));
        reloadAnalyzersRequest.indicesOptions(IndicesOptions.fromRequest(request, reloadAnalyzersRequest.indicesOptions()));
        return channel -> client.admin().indices().reloadAnalyzers(reloadAnalyzersRequest, new RestToXContentListener<>(channel));
    }
}
