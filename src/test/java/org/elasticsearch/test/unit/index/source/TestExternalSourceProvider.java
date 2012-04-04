/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

package org.elasticsearch.test.unit.index.source;

import org.elasticsearch.common.BytesHolder;
import org.elasticsearch.common.io.stream.CachedStreamOutput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.index.source.ExternalSourceProvider;

import java.io.IOException;
import java.util.Map;

import static com.google.common.collect.Maps.newHashMap;

/**
 *
 */
public class TestExternalSourceProvider implements ExternalSourceProvider {
    @Override
    public BytesHolder dehydrateSource(String type, String id, byte[] source, int sourceOffset, int sourceLength) throws IOException {
        Map<String, Object> dehydratedSource = newHashMap();
        dehydratedSource.put("dehydrated", true);
        CachedStreamOutput.Entry cachedEntry = CachedStreamOutput.popEntry();
        try {
            StreamOutput streamOutput = cachedEntry.cachedBytes();
            XContentBuilder builder = XContentFactory.jsonBuilder(streamOutput).map(dehydratedSource);
            builder.close();
            return new BytesHolder(cachedEntry.bytes().copiedByteArray());
        } finally {
            CachedStreamOutput.pushEntry(cachedEntry);
        }
    }

    @Override
    public BytesHolder rehydrateSource(String type, String id, byte[] source, int sourceOffset, int sourceLength) {
        StringBuilder builder = new StringBuilder();
        builder.append("--");
        builder.append(type);
        builder.append("--");
        builder.append(id);
        builder.append("--");
        builder.append(new String(source, sourceOffset, sourceLength));
        builder.append("--");
        return new BytesHolder(builder.toString().getBytes());
    }

    @Override
    public boolean enabled() {
        return true;
    }
}
