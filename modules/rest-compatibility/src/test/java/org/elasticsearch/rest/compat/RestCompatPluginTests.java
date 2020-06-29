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

package org.elasticsearch.rest.compat;

import org.elasticsearch.Version;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.test.ESTestCase;
import org.hamcrest.Matchers;

import java.util.List;

public class RestCompatPluginTests extends ESTestCase {

    public void testRestHandlersValidation() {
        RestCompatPlugin restCompatPlugin = new RestCompatPlugin();
        Version prevVersion = Version.fromString("7.0.0");
        expectThrows(IllegalStateException.class, () ->
            restCompatPlugin.validateCompatibleHandlers(7, restHandler(prevVersion), restHandler(Version.fromString("8.0.0"))));

        List<RestHandler> restHandlers = restCompatPlugin.validateCompatibleHandlers(7, restHandler(prevVersion), restHandler(prevVersion));
        assertThat(restHandlers, Matchers.hasSize(2));
    }

    private RestHandler restHandler(final Version version) {
        return new RestHandler() {
            @Override
            public Version compatibleWithVersion() {
                return version;
            }

            @Override
            public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {

            }
        };
    }
}
