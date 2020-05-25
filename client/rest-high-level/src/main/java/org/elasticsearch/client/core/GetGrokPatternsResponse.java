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

package org.elasticsearch.client.core;

import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.Map;

public class GetGrokPatternsResponse {
    private final Map<String, String> grokPatterns;

    GetGrokPatternsResponse(Map<String, String> grokPatterns) {
        this.grokPatterns = grokPatterns;
    }

    public Map<String, String> getGrokPatterns() {
        return grokPatterns;
    }

    public static GetGrokPatternsResponse fromXContent(XContentParser parser) throws IOException {
        return new GetGrokPatternsResponse(parser.mapStrings());
    }

    @Override
    public String toString() {
        return grokPatterns.toString();
    }
}
