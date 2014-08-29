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

package org.elasticsearch.cluster;

import org.elasticsearch.action.ActionRequestBuilder;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.percolate.PercolateSourceBuilder;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.discovery.Discovery;
import org.elasticsearch.discovery.MasterNotDiscoveredException;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.test.ElasticsearchIntegrationTest;
import org.elasticsearch.test.ElasticsearchIntegrationTest.ClusterScope;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.junit.Test;

import java.util.HashMap;

import static org.elasticsearch.action.percolate.PercolateSourceBuilder.docBuilder;
import static org.elasticsearch.common.settings.ImmutableSettings.settingsBuilder;
import static org.elasticsearch.test.ElasticsearchIntegrationTest.Scope;
import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertThrows;
import static org.hamcrest.Matchers.*;

/**
 */
@ClusterScope(scope = Scope.TEST, numDataNodes = 0)
public class NoMasterNodeTests extends ElasticsearchIntegrationTest {

    @Test
    @TestLogging("action:TRACE,cluster.service:TRACE")
    public void testNoMasterActions() throws Exception {
        // note, sometimes, we want to check with the fact that an index gets created, sometimes not...
        boolean autoCreateIndex = randomBoolean();
        logger.info("auto_create_index set to {}", autoCreateIndex);

        Settings settings = settingsBuilder()
                .put("discovery.type", "zen")
                .put("action.auto_create_index", autoCreateIndex)
                .put("discovery.zen.minimum_master_nodes", 2)
                .put("discovery.zen.ping_timeout", "200ms")
                .put("discovery.initial_state_timeout", "500ms")
                .build();

        TimeValue timeout = TimeValue.timeValueMillis(200);

        internalCluster().startNode(settings);
        // start a second node, create an index, and then shut it down so we have no master block
        internalCluster().startNode(settings);
        createIndex("test");
        client().admin().cluster().prepareHealth("test").setWaitForGreenStatus().execute().actionGet();
        internalCluster().stopRandomDataNode();
        assertBusy(new Runnable() {
            @Override
            public void run() {
                ClusterState state = client().admin().cluster().prepareState().setLocal(true).execute().actionGet().getState();
                assertTrue(state.blocks().hasGlobalBlock(Discovery.NO_MASTER_BLOCK));
            }
        });

        assertThrows(client().prepareGet("test", "type1", "1"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        assertThrows(client().prepareGet("no_index", "type1", "1"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        assertThrows(client().prepareMultiGet().add("test", "type1", "1"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        assertThrows(client().prepareMultiGet().add("no_index", "type1", "1"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        PercolateSourceBuilder percolateSource = new PercolateSourceBuilder();
        percolateSource.setDoc(docBuilder().setDoc(new HashMap()));
        assertThrows(client().preparePercolate()
                        .setIndices("test").setDocumentType("type1")
                        .setSource(percolateSource),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        percolateSource = new PercolateSourceBuilder();
        percolateSource.setDoc(docBuilder().setDoc(new HashMap()));
        assertThrows(client().preparePercolate()
                        .setIndices("no_index").setDocumentType("type1")
                        .setSource(percolateSource),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );


        assertThrows(client().admin().indices().prepareAnalyze("test", "this is a test"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        assertThrows(client().admin().indices().prepareAnalyze("no_index", "this is a test"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        assertThrows(client().prepareCount("test"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        assertThrows(client().prepareCount("no_index"),
                ClusterBlockException.class, RestStatus.SERVICE_UNAVAILABLE
        );

        checkWriteAction(autoCreateIndex, timeout,
                client().prepareUpdate("test", "type1", "1").setScript("test script", ScriptService.ScriptType.INLINE).setTimeout(timeout));


        checkWriteAction(autoCreateIndex, timeout,
                client().prepareUpdate("no_index", "type1", "1").setScript("test script", ScriptService.ScriptType.INLINE).setTimeout(timeout));


        checkWriteAction(autoCreateIndex, timeout,
                client().prepareIndex("test", "type1", "1").setSource(XContentFactory.jsonBuilder().startObject().endObject()).setTimeout(timeout));

        checkWriteAction(autoCreateIndex, timeout,
                client().prepareIndex("no_index", "type1", "1").setSource(XContentFactory.jsonBuilder().startObject().endObject()).setTimeout(timeout));

        BulkRequestBuilder bulkRequestBuilder = client().prepareBulk();
        bulkRequestBuilder.add(client().prepareIndex("test", "type1", "1").setSource(XContentFactory.jsonBuilder().startObject().endObject()));
        bulkRequestBuilder.add(client().prepareIndex("test", "type1", "2").setSource(XContentFactory.jsonBuilder().startObject().endObject()));
        bulkRequestBuilder.setTimeout(timeout);
        checkBulkAction(autoCreateIndex, timeout, bulkRequestBuilder);

        bulkRequestBuilder = client().prepareBulk();
        bulkRequestBuilder.add(client().prepareIndex("no_index", "type1", "1").setSource(XContentFactory.jsonBuilder().startObject().endObject()));
        bulkRequestBuilder.add(client().prepareIndex("no_index", "type1", "2").setSource(XContentFactory.jsonBuilder().startObject().endObject()));
        bulkRequestBuilder.setTimeout(timeout);
        checkBulkAction(autoCreateIndex, timeout, bulkRequestBuilder);

        internalCluster().startNode(settings);
        client().admin().cluster().prepareHealth().setWaitForGreenStatus().setWaitForNodes("2").execute().actionGet();
    }

    void checkWriteAction(boolean autoCreateIndex, TimeValue timeout, ActionRequestBuilder<?, ?, ?, ?> builder) {
        // we clean the metadata when loosing a master, therefore all operations on indices will auto create it, if allowed
        long now = System.currentTimeMillis();
        try {
            builder.get();
            fail("expected ClusterBlockException or MasterNotDiscoveredException");
        } catch (ClusterBlockException | MasterNotDiscoveredException e) {
            if (e instanceof MasterNotDiscoveredException) {
                assertTrue(autoCreateIndex);
            } else {
                assertFalse(autoCreateIndex);
            }
            // verify we waited before giving up...
            assertThat(e.status(), equalTo(RestStatus.SERVICE_UNAVAILABLE));
            assertThat(System.currentTimeMillis() - now, greaterThan(timeout.millis() - 50));
        }
    }

    void checkBulkAction(boolean autoCreateIndex, TimeValue timeout, BulkRequestBuilder builder) {
        // bulk operation do not throw MasterNotDiscoveredException exceptions. The only test that auto create kicked in and failed is
        // via the timeout, as they do not wait on block :(

        long now = System.currentTimeMillis();
        try {
            builder.get();
            fail("Expected ClusterBlockException");
        } catch (ClusterBlockException e) {
            // today, we clear the metadata on when there is no master, so it will go through the auto create logic and
            // add it... (if set to true), if we didn't remove the metedata when there is no master, then, the non
            // retry in bulk should be taken into account
            if (!autoCreateIndex) {
                assertThat(System.currentTimeMillis() - now, lessThan(timeout.millis() / 2));
            } else {
                assertThat(System.currentTimeMillis() - now, greaterThan(timeout.millis() - 50));
                assertThat(e.status(), equalTo(RestStatus.SERVICE_UNAVAILABLE));
            }
        }
    }
}
