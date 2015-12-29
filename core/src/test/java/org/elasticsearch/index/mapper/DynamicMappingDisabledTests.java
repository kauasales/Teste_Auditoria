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

package org.elasticsearch.index.mapper;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.index.TransportIndexAction;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.AutoCreateIndex;
import org.elasticsearch.cluster.action.shard.ShardStateAction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.indices.IndicesService;
import org.elasticsearch.test.ESSingleNodeTestCase;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.transport.local.LocalTransport;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.test.cluster.TestClusterService;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.util.Collections;
import java.util.concurrent.TimeUnit;

public class DynamicMappingDisabledTests extends ESSingleNodeTestCase {

    private static ThreadPool THREAD_POOL;
    private TestClusterService clusterService;
    private LocalTransport transport;
    private TransportService transportService;
    private IndicesService indicesService;
    private ShardStateAction shardStateAction;
    private ActionFilters actionFilters;
    private IndexNameExpressionResolver indexNameExpressionResolver;
    private AutoCreateIndex autoCreateIndex;
    private Settings settings;

    private class DynamicMappingDisabledTestActionListener implements ActionListener<IndexResponse> {
        boolean onFailureCalled = false;
        public boolean getOnFailureCalled() {
            return onFailureCalled;
        }

        public void setOnFailureCalled(boolean onFailureCalled) {
            this.onFailureCalled = onFailureCalled;
        }

        @Override
        public void onResponse(IndexResponse indexResponse) {
            fail("Indexing request should have failed");
        }

        @Override
        public void onFailure(Throwable e) {
            setOnFailureCalled(true);
            assert(e instanceof IndexNotFoundException);
            assertEquals(e.getMessage(), "no such index");
        }
    }

    @BeforeClass
    public static void createThreadPool() {
        THREAD_POOL = new ThreadPool("DynamicMappingDisabledTests");
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        settings = Settings.builder()
            .put(MapperService.INDEX_MAPPER_DYNAMIC_SETTING, "false")
            .build();
        clusterService = new TestClusterService(THREAD_POOL);
        transport = new LocalTransport(settings, THREAD_POOL, Version.CURRENT, new NamedWriteableRegistry());
        transportService = new TransportService(transport, THREAD_POOL);
        indicesService = getInstanceFromNode(IndicesService.class);
        shardStateAction = new ShardStateAction(settings, clusterService, transportService, null, null);
        actionFilters = new ActionFilters(Collections.emptySet());
        indexNameExpressionResolver = new IndexNameExpressionResolver(settings);
        autoCreateIndex = new AutoCreateIndex(settings, indexNameExpressionResolver);
    }

    @AfterClass
    public static void destroyThreadPool() {
        ThreadPool.terminate(THREAD_POOL, 30, TimeUnit.SECONDS);
        THREAD_POOL = null;
    }

    public void testDynamicDisabled() {
        TransportIndexAction action = new TransportIndexAction(settings, transportService, clusterService,
            indicesService, THREAD_POOL, shardStateAction, null, null, actionFilters, indexNameExpressionResolver,
            autoCreateIndex);

        IndexRequest request = new IndexRequest("index", "type", "1");
        request.source("foo", 3);
        DynamicMappingDisabledTestActionListener listener = new DynamicMappingDisabledTestActionListener();

        action.execute(request, listener);

        assert(listener.getOnFailureCalled());
    }
}
