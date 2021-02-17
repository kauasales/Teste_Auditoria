/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.ingest.geoip;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.node.Node;
import org.elasticsearch.persistent.AllocatedPersistentTask;
import org.elasticsearch.persistent.PersistentTaskState;
import org.elasticsearch.persistent.PersistentTasksCustomMetadata.PersistentTask;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.client.NoOpClient;
import org.elasticsearch.threadpool.ThreadPool;
import org.junit.After;
import org.junit.Before;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;

import static org.elasticsearch.ingest.geoip.GeoIpDownloader.ENDPOINT_SETTING;
import static org.elasticsearch.ingest.geoip.GeoIpDownloader.MAX_CHUNK_SIZE;
import static org.elasticsearch.tasks.TaskId.EMPTY_TASK_ID;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class GeoIpDownloaderTests extends ESTestCase {

    private HttpClient httpClient;
    private ClusterService clusterService;
    private ThreadPool threadPool;
    private MockClient client;
    private GeoIpDownloader geoIpDownloader;

    @Before
    public void setup() {
        httpClient = mock(HttpClient.class);
        clusterService = mock(ClusterService.class);
        threadPool = new ThreadPool(Settings.builder().put(Node.NODE_NAME_SETTING.getKey(), "test").build());
        when(clusterService.getClusterSettings()).thenReturn(new ClusterSettings(Settings.EMPTY,
            Set.of(GeoIpDownloader.ENDPOINT_SETTING, GeoIpDownloader.POLL_INTERVAL_SETTING, GeoIpDownloaderTaskExecutor.ENABLED_SETTING)));
        ClusterState state = ClusterState.builder(ClusterName.DEFAULT).build();
        when(clusterService.state()).thenReturn(state);
        client = new MockClient(threadPool);
        geoIpDownloader = new GeoIpDownloader(client, httpClient, clusterService, threadPool, Settings.EMPTY,
            1, "", "", "", EMPTY_TASK_ID, Collections.emptyMap());
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        threadPool.shutdownNow();
    }

    public void testGetChunkEndOfStream() throws IOException {
        byte[] chunk = geoIpDownloader.getChunk(new InputStream() {
            @Override
            public int read() {
                return -1;
            }
        });
        assertArrayEquals(new byte[0], chunk);
        chunk = geoIpDownloader.getChunk(new ByteArrayInputStream(new byte[0]));
        assertArrayEquals(new byte[0], chunk);
    }

    public void testGetChunkLessThanChunkSize() throws IOException {
        ByteArrayInputStream is = new ByteArrayInputStream(new byte[]{1, 2, 3, 4});
        byte[] chunk = geoIpDownloader.getChunk(is);
        assertArrayEquals(new byte[]{1, 2, 3, 4}, chunk);
        chunk = geoIpDownloader.getChunk(is);
        assertArrayEquals(new byte[0], chunk);

    }

    public void testGetChunkExactlyChunkSize() throws IOException {
        byte[] bigArray = new byte[MAX_CHUNK_SIZE];
        for (int i = 0; i < MAX_CHUNK_SIZE; i++) {
            bigArray[i] = (byte) i;
        }
        ByteArrayInputStream is = new ByteArrayInputStream(bigArray);
        byte[] chunk = geoIpDownloader.getChunk(is);
        assertArrayEquals(bigArray, chunk);
        chunk = geoIpDownloader.getChunk(is);
        assertArrayEquals(new byte[0], chunk);
    }

    public void testGetChunkMoreThanChunkSize() throws IOException {
        byte[] bigArray = new byte[MAX_CHUNK_SIZE * 2];
        for (int i = 0; i < MAX_CHUNK_SIZE * 2; i++) {
            bigArray[i] = (byte) i;
        }
        byte[] smallArray = new byte[MAX_CHUNK_SIZE];
        System.arraycopy(bigArray, 0, smallArray, 0, MAX_CHUNK_SIZE);
        ByteArrayInputStream is = new ByteArrayInputStream(bigArray);
        byte[] chunk = geoIpDownloader.getChunk(is);
        assertArrayEquals(smallArray, chunk);
        System.arraycopy(bigArray, MAX_CHUNK_SIZE, smallArray, 0, MAX_CHUNK_SIZE);
        chunk = geoIpDownloader.getChunk(is);
        assertArrayEquals(smallArray, chunk);
        chunk = geoIpDownloader.getChunk(is);
        assertArrayEquals(new byte[0], chunk);
    }

    public void testGetChunkRethrowsIOException() {
        expectThrows(IOException.class, () -> geoIpDownloader.getChunk(new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException();
            }
        }));
    }

    public void testIndexChunksNoData() throws IOException {
        assertEquals(0, geoIpDownloader.indexChunks("test", new ByteArrayInputStream(new byte[0]), 0));
    }

    public void testIndexChunks() throws IOException {
        byte[] bigArray = new byte[MAX_CHUNK_SIZE + 20];
        for (int i = 0; i < MAX_CHUNK_SIZE + 20; i++) {
            bigArray[i] = (byte) i;
        }
        byte[][] chunksData = new byte[2][];
        chunksData[0] = new byte[MAX_CHUNK_SIZE];
        System.arraycopy(bigArray, 0, chunksData[0], 0, MAX_CHUNK_SIZE);
        chunksData[1] = new byte[20];
        System.arraycopy(bigArray, MAX_CHUNK_SIZE, chunksData[1], 0, 20);

        AtomicInteger chunkIndex = new AtomicInteger();

        client.addHandler(IndexAction.INSTANCE, (IndexRequest request, ActionListener<IndexResponse> listener) -> {
            int chunk = chunkIndex.getAndIncrement();
            assertEquals("test_" + (chunk + 15), request.id());
            assertEquals(XContentType.SMILE, request.getContentType());
            Map<String, Object> source = request.sourceAsMap();
            assertEquals("test", source.get("name"));
            assertArrayEquals(chunksData[chunk], (byte[]) source.get("data"));
            assertEquals(chunk + 15, source.get("chunk"));
            listener.onResponse(mock(IndexResponse.class));
        });

        assertEquals(17, geoIpDownloader.indexChunks("test", new ByteArrayInputStream(bigArray), 15));

        assertEquals(2, chunkIndex.get());
    }

    public void testProcessDatabaseNew() throws IOException {
        GeoIpTaskState taskState = new GeoIpTaskState();

        ByteArrayInputStream bais = new ByteArrayInputStream(new byte[0]);
        when(httpClient.get("a.b/t1")).thenReturn(bais);

        geoIpDownloader = new GeoIpDownloader(client, httpClient, clusterService, threadPool, Settings.EMPTY,
            1, "", "", "", EMPTY_TASK_ID, Collections.emptyMap()) {
            @Override
            boolean updateTaskState(String name) {
                assertEquals(0, state.getDatabases().get("test").getFirstChunk());
                assertEquals(10, state.getDatabases().get("test").getLastChunk());
                assertEquals("test", name);
                return true;
            }

            @Override
            int indexChunks(String name, InputStream is, int chunk) {
                assertSame(bais, is);
                assertEquals(0, chunk);
                return 11;
            }

            @Override
            protected void updateTimestamp(Map<String, GeoIpTaskState.Metadata> currentDatabases, String name) {
                fail();
            }

            @Override
            void deleteOldChunks(String name, int firstChunk) {
                assertEquals("test", name);
                assertEquals(0, firstChunk);
            }
        };

        geoIpDownloader.setState(taskState);
        geoIpDownloader.processDatabase(Map.of("name", "test.gz", "url", "a.b/t1", "md5_hash", "1"));
    }

    public void testProcessDatabaseUpdate() throws IOException {
        GeoIpTaskState taskState = new GeoIpTaskState();
        taskState.getDatabases().put("test", new GeoIpTaskState.Metadata(0, 5, 8, "0"));

        ByteArrayInputStream bais = new ByteArrayInputStream(new byte[0]);
        when(httpClient.get("a.b/t1")).thenReturn(bais);

        geoIpDownloader = new GeoIpDownloader(client, httpClient, clusterService, threadPool, Settings.EMPTY,
            1, "", "", "", EMPTY_TASK_ID, Collections.emptyMap()) {
            @Override
            boolean updateTaskState(String name) {
                assertEquals(9, state.getDatabases().get("test").getFirstChunk());
                assertEquals(10, state.getDatabases().get("test").getLastChunk());
                assertEquals("test", name);
                return true;
            }

            @Override
            int indexChunks(String name, InputStream is, int chunk) {
                assertSame(bais, is);
                assertEquals(9, chunk);
                return 11;
            }

            @Override
            protected void updateTimestamp(Map<String, GeoIpTaskState.Metadata> currentDatabases, String name) {
                fail();
            }

            @Override
            void deleteOldChunks(String name, int firstChunk) {
                assertEquals("test", name);
                assertEquals(9, firstChunk);
            }
        };

        geoIpDownloader.setState(taskState);
        geoIpDownloader.processDatabase(Map.of("name", "test.gz", "url", "a.b/t1", "md5_hash", "1"));
    }


    public void testProcessDatabaseSame() throws IOException {
        GeoIpTaskState taskState = new GeoIpTaskState();
        Map<String, GeoIpTaskState.Metadata> databases = taskState.getDatabases();
        databases.put("test", new GeoIpTaskState.Metadata(0, 4, 10, "1"));

        ByteArrayInputStream bais = new ByteArrayInputStream(new byte[0]);
        when(httpClient.get("a.b/t1")).thenReturn(bais);

        geoIpDownloader = new GeoIpDownloader(client, httpClient, clusterService, threadPool, Settings.EMPTY,
            1, "", "", "", EMPTY_TASK_ID, Collections.emptyMap()) {
            @Override
            boolean updateTaskState(String name) {
                fail();
                return true;
            }

            @Override
            int indexChunks(String name, InputStream is, int chunk) {
                fail();
                return 0;
            }

            @Override
            protected void updateTimestamp(Map<String, GeoIpTaskState.Metadata> currentDatabases, String name) {
                assertEquals(databases, currentDatabases);
                assertEquals("test", name);
            }

            @Override
            void deleteOldChunks(String name, int firstChunk) {
                fail();
            }
        };

        geoIpDownloader.setState(taskState);
        geoIpDownloader.processDatabase(Map.of("name", "test.gz", "url", "a.b/t1", "md5_hash", "1"));
    }

    @SuppressWarnings("unchecked")
    public void testUpdateTaskState() {
        GeoIpTaskState taskState = new GeoIpTaskState();
        geoIpDownloader = new GeoIpDownloader(client, httpClient, clusterService, threadPool, Settings.EMPTY,
            1, "", "", "", EMPTY_TASK_ID, Collections.emptyMap()) {
            @Override
            public void updatePersistentTaskState(PersistentTaskState state, ActionListener<PersistentTask<?>> listener) {
                assertSame(taskState, state);
                PersistentTask<?> task = mock(PersistentTask.class);
                when(task.getState()).thenReturn(taskState);
                listener.onResponse(task);
            }
        };
        geoIpDownloader.setState(taskState);
        assertTrue(geoIpDownloader.updateTaskState("test"));
    }

    @SuppressWarnings("unchecked")
    public void testUpdateTaskStateError() {
        AllocatedPersistentTask mock = mock(AllocatedPersistentTask.class);
        GeoIpTaskState taskState = new GeoIpTaskState();
        geoIpDownloader = new GeoIpDownloader(client, httpClient, clusterService, threadPool, Settings.EMPTY,
            1, "", "", "", EMPTY_TASK_ID, Collections.emptyMap()) {
            @Override
            public void updatePersistentTaskState(PersistentTaskState state, ActionListener<PersistentTask<?>> listener) {
                assertSame(taskState, state);
                PersistentTask<?> task = mock(PersistentTask.class);
                when(task.getState()).thenReturn(taskState);
                listener.onFailure(new IllegalStateException("test failure"));
            }
        };
        geoIpDownloader.setState(taskState);
        assertFalse(geoIpDownloader.updateTaskState("test"));
    }

    public void testUpdateDatabases() throws IOException {
        List<Map<String, Object>> maps = List.of(Map.of("a", 1), Map.of("a", 2));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XContentBuilder builder = new XContentBuilder(XContentType.JSON.xContent(), baos);
        builder.startArray();
        builder.map(Map.of("a", 1));
        builder.map(Map.of("a", 2));
        builder.endArray();
        builder.close();
        when(httpClient.getBytes("a.b?key=11111111-1111-1111-1111-111111111111")).thenReturn(baos.toByteArray());
        Iterator<Map<String, Object>> it = maps.iterator();
        geoIpDownloader = new GeoIpDownloader(client, httpClient, clusterService, threadPool,
            Settings.builder().put(ENDPOINT_SETTING.getKey(), "a.b").build(),
            1, "", "", "", EMPTY_TASK_ID, Collections.emptyMap()) {
            @Override
            void processDatabase(Map<String, Object> databaseInfo) {
                assertEquals(it.next(), databaseInfo);
            }
        };
        geoIpDownloader.updateDatabases();
        assertFalse(it.hasNext());
    }

    private static class MockClient extends NoOpClient {

        private final Map<ActionType<?>, BiConsumer<? extends ActionRequest, ? extends ActionListener<?>>> handlers = new HashMap<>();

        private MockClient(ThreadPool threadPool) {
            super(threadPool);
        }

        public <Response extends ActionResponse, Request extends ActionRequest> void addHandler(ActionType<Response> action,
                                                                                                BiConsumer<Request,
                                                                                                    ActionListener<Response>> listener) {
            handlers.put(action, listener);
        }

        @SuppressWarnings("unchecked")
        @Override
        protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(ActionType<Response> action,
                                                                                                  Request request,
                                                                                                  ActionListener<Response> listener) {
            if (handlers.containsKey(action)) {
                BiConsumer<ActionRequest, ActionListener<?>> biConsumer =
                    (BiConsumer<ActionRequest, ActionListener<?>>) handlers.get(action);
                biConsumer.accept(request, listener);
            } else {
                throw new IllegalStateException("unexpected action called [" + action.name() + "]");
            }
        }
    }
}
