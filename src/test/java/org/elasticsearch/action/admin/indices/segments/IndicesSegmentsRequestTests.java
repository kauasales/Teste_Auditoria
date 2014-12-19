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

package org.elasticsearch.action.admin.indices.segments;

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.engine.Segment;
import org.elasticsearch.test.ElasticsearchSingleNodeTest;
import org.junit.Before;

import java.util.List;

public class IndicesSegmentsRequestTests extends ElasticsearchSingleNodeTest {
    
    @Before
    public void setupIndex() {
        Settings settings = ImmutableSettings.builder()
            // don't allow any merges so that the num docs is the expected segments
            .put("index.merge.policy.segments_per_tier", 1000000f)
            .build();
        createIndex("test", settings);

        int numDocs = scaledRandomIntBetween(100, 1000);
        for (int j = 0; j < numDocs; ++j) {
            String id = Integer.toString(j);
            client().prepareIndex("test", "type1", id).setSource("text", "sometext").get();
        }
        client().admin().indices().prepareFlush("test").get();
    }

    public void testBasic() {
        IndicesSegmentResponse rsp = client().admin().indices().prepareSegments("test").get();
        List<Segment> segments = rsp.getIndices().get("test").iterator().next().getShards()[0].getSegments();
        assertNull(segments.get(0).ramTree);
    }
    
    public void testVerbose() {
        IndicesSegmentResponse rsp = client().admin().indices().prepareSegments("test").setVerbose(true).get();
        List<Segment> segments = rsp.getIndices().get("test").iterator().next().getShards()[0].getSegments();
        assertNotNull(segments.get(0).ramTree);
    }
}
