package org.elasticsearch.action.bulk;

import org.apache.lucene.util.Constants;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.create.TransportCreateIndexAction;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.AutoCreateIndex;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetaDataCreateIndexService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.AtomicArray;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.cluster.TestClusterService;
import org.elasticsearch.test.transport.CapturingTransport;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import static org.elasticsearch.test.StreamsUtils.copyToStringFromClasspath;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.mockito.Mockito.mock;

public class TransportBulkActionTookTests extends ESTestCase {

    private ThreadPool threadPool;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        threadPool = mock(ThreadPool.class);
    }

    private TransportBulkAction createAction(boolean controlled, AtomicLong expected) {
        CapturingTransport capturingTransport = new CapturingTransport();
        ClusterService clusterService = new TestClusterService(threadPool);
        TransportService transportService = new TransportService(capturingTransport, threadPool);
        transportService.start();
        transportService.acceptIncomingRequests();
        IndexNameExpressionResolver resolver = new Resolver(Settings.EMPTY);
        ActionFilters actionFilters = new ActionFilters(new HashSet<>());

        TransportCreateIndexAction createIndexAction = new TransportCreateIndexAction(
                Settings.EMPTY,
                transportService,
                clusterService,
                threadPool,
                null,
                actionFilters,
                resolver);

        if (controlled) {

            return new TestTransportBulkAction(
                    Settings.EMPTY,
                    threadPool,
                    transportService,
                    clusterService,
                    null,
                    createIndexAction,
                    actionFilters,
                    resolver,
                    null,
                    expected::get) {
                @Override
                public void executeBulk(BulkRequest bulkRequest, ActionListener<BulkResponse> listener) {
                    expected.set(1000000);
                    super.executeBulk(bulkRequest, listener);
                }

                @Override
                void executeBulk(
                        BulkRequest bulkRequest,
                        long startTimeNanos,
                        ActionListener<BulkResponse> listener,
                        AtomicArray<BulkItemResponse> responses) {
                    expected.set(1000000);
                    super.executeBulk(bulkRequest, startTimeNanos, listener, responses);
                }
            };
        } else {
            return new TestTransportBulkAction(
                    Settings.EMPTY,
                    threadPool,
                    transportService,
                    clusterService,
                    null,
                    createIndexAction,
                    actionFilters,
                    resolver,
                    null,
                    System::nanoTime) {
                @Override
                public void executeBulk(BulkRequest bulkRequest, ActionListener<BulkResponse> listener) {
                    long elapsed = spinForAtLeastOneMillisecond();
                    expected.set(elapsed);
                    super.executeBulk(bulkRequest, listener);
                }

                @Override
                void executeBulk(
                        BulkRequest bulkRequest,
                        long startTimeNanos,
                        ActionListener<BulkResponse> listener,
                        AtomicArray<BulkItemResponse> responses) {
                    long elapsed = spinForAtLeastOneMillisecond();
                    expected.set(elapsed);
                    super.executeBulk(bulkRequest, startTimeNanos, listener, responses);
                }
            };
        }
    }

    // test unit conversion with a controlled clock
    public void testTookWithControlledClock() throws Exception {
        runTestTook(true);
    }

    // test took advances with System#nanoTime
    public void testTookWithRealClock() throws Exception {
        runTestTook(false);
    }

    private void runTestTook(boolean controlled) throws Exception {
        String bulkAction = copyToStringFromClasspath("/org/elasticsearch/action/bulk/simple-bulk.json");
        // translate Windows line endings (\r\n) to standard ones (\n)
        if (Constants.WINDOWS) {
            bulkAction = Strings.replace(bulkAction, "\r\n", "\n");
        }
        BulkRequest bulkRequest = new BulkRequest();
        bulkRequest.add(bulkAction.getBytes(StandardCharsets.UTF_8), 0, bulkAction.length(), null, null);
        AtomicLong expected = new AtomicLong();
        TransportBulkAction action = createAction(controlled, expected);
        action.doExecute(bulkRequest, new ActionListener<BulkResponse>() {
            @Override
            public void onResponse(BulkResponse bulkItemResponses) {
                if (controlled) {
                    assertThat(
                            bulkItemResponses.getTook().getMillis(),
                            equalTo(TimeUnit.MILLISECONDS.convert(expected.get(), TimeUnit.NANOSECONDS)));
                } else {
                    assertThat(
                            bulkItemResponses.getTook().getMillis(),
                            greaterThanOrEqualTo(TimeUnit.MILLISECONDS.convert(expected.get(), TimeUnit.NANOSECONDS)));
                }
            }

            @Override
            public void onFailure(Throwable e) {

            }
        });
    }

    static class Resolver extends IndexNameExpressionResolver {
        public Resolver(Settings settings) {
            super(settings);
        }

        @Override
        public String[] concreteIndices(ClusterState state, IndicesRequest request) {
            return request.indices();
        }
    }

    static class TestTransportBulkAction extends TransportBulkAction {

        public TestTransportBulkAction(
                Settings settings,
                ThreadPool threadPool,
                TransportService transportService,
                ClusterService clusterService,
                TransportShardBulkAction shardBulkAction,
                TransportCreateIndexAction createIndexAction,
                ActionFilters actionFilters,
                IndexNameExpressionResolver indexNameExpressionResolver,
                AutoCreateIndex autoCreateIndex,
                LongSupplier relativeTimeProvider) {
            super(
                    settings,
                    threadPool,
                    transportService,
                    clusterService,
                    shardBulkAction,
                    createIndexAction,
                    actionFilters,
                    indexNameExpressionResolver,
                    autoCreateIndex,
                    relativeTimeProvider);
        }

        @Override
        boolean needToCheck() {
            return randomBoolean();
        }

        @Override
        boolean shouldAutoCreate(String index, ClusterState state) {
            return randomBoolean();
        }

    }

    static class TestTransportCreateIndexAction extends TransportCreateIndexAction {

        public TestTransportCreateIndexAction(
                Settings settings,
                TransportService transportService,
                ClusterService clusterService,
                ThreadPool threadPool,
                MetaDataCreateIndexService createIndexService,
                ActionFilters actionFilters,
                IndexNameExpressionResolver indexNameExpressionResolver) {
            super(settings, transportService, clusterService, threadPool, createIndexService, actionFilters, indexNameExpressionResolver);
        }

        @Override
        protected void doExecute(Task task, CreateIndexRequest request, ActionListener<CreateIndexResponse> listener) {
            listener.onResponse(new CreateIndexResponse(true));
        }
    }

}
