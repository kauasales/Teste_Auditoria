package org.elasticsearch.xpack.enrich;

import java.util.Arrays;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.admin.indices.get.GetIndexRequest;
import org.elasticsearch.action.admin.indices.get.GetIndexResponse;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.LocalNodeMasterListener;
import org.elasticsearch.cluster.metadata.MappingMetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.EsRejectedExecutionException;
import org.elasticsearch.common.xcontent.ObjectPath;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.threadpool.Scheduler;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.core.enrich.EnrichPolicy;

public class EnrichPolicyMaintenanceService implements LocalNodeMasterListener {

    private static final Logger logger = LogManager.getLogger(EnrichPolicyMaintenanceService.class);

    private static final String MAPPING_POLICY_FIELD_PATH = MapperService.SINGLE_MAPPING_NAME + "._meta." +
        EnrichPolicyRunner.ENRICH_POLICY_FIELD_NAME;
    private static final IndicesOptions IGNORE_UNAVAILABLE = IndicesOptions.fromOptions(true, false, false, false);

    private final Settings settings;
    private final Client client;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final EnrichPolicyLocks enrichPolicyLocks;

    private volatile Scheduler.Cancellable cancellable;

    EnrichPolicyMaintenanceService(Settings settings, Client client, ClusterService clusterService, ThreadPool threadPool,
                                   EnrichPolicyLocks enrichPolicyLocks) {
        this.settings = settings;
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.enrichPolicyLocks = enrichPolicyLocks;
    }

    void initialize() {
        clusterService.addLocalNodeMasterListener(this);
    }

    @Override
    public void onMaster() {
        if (cancellable == null || cancellable.isCancelled()) {
            scheduleNext();
            clusterService.addLifecycleListener(new LifecycleListener() {
                @Override
                public void beforeStop() {
                    offMaster();
                }
            });
        }
    }

    @Override
    public void offMaster() {
        if (cancellable != null && cancellable.isCancelled() == false) {
            cancellable.cancel();
        }
    }

    @Override
    public String executorName() {
        return ThreadPool.Names.GENERIC;
    }

    private void scheduleNext() {
        try {
            TimeValue waitTime = EnrichPlugin.ENRICH_CLEANUP_PERIOD.get(settings);
            cancellable = threadPool.schedule(this::execute, waitTime, ThreadPool.Names.GENERIC);
        } catch (EsRejectedExecutionException e) {
            if (e.isExecutorShutdown()) {
                logger.debug("failed to schedule next [enrich] maintenance task; shutting down", e);
            } else {
                throw e;
            }
        }
    }

    private void execute() {
        logger.debug("triggering scheduled [enrich] maintenance task");
        cleanUpEnrichIndices();
        scheduleNext();
    }

    private void cleanUpEnrichIndices() {
        final Map<String, EnrichPolicy> policies = EnrichStore.getPolicies(clusterService.state());
        GetIndexRequest indices = new GetIndexRequest()
            .indices(EnrichPolicy.ENRICH_INDEX_NAME_BASE + "*")
            .indicesOptions(IndicesOptions.lenientExpand());
        // Check that no enrich policies are being executed
        final EnrichPolicyLocks.LockState lockState = enrichPolicyLocks.lockState();
        if (lockState.runningPolicies == false) {
            client.admin().indices().getIndex(indices, new ActionListener<>() {
                @Override
                public void onResponse(GetIndexResponse getIndexResponse) {
                    // Ensure that no enrich policy executions started while we were retrieving the snapshot of index data
                    // If executions were kicked off, we can't be sure that the indices we are about to process are a
                    // stable state of the system (they could be new indices created by a policy that hasn't been published yet).
                    if (enrichPolicyLocks.isSafe(lockState)) {
                        String[] removeIndices = Arrays.stream(getIndexResponse.getIndices())
                            .filter(indexName -> shouldRemoveIndex(getIndexResponse, policies, indexName))
                            .toArray(String[]::new);
                        deleteIndices(removeIndices);
                    } else {
                        logger.debug("Skipping enrich index cleanup since enrich policy was executed while gathering indices");
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    logger.error("Failed to get indices during enrich index maintenance task", e);
                }
            });
        }
    }

    private boolean shouldRemoveIndex(GetIndexResponse getIndexResponse, Map<String, EnrichPolicy> policies, String indexName) {
        // Find the policy on the index
        ImmutableOpenMap<String, MappingMetaData> indexMapping = getIndexResponse.getMappings().get(indexName);
        MappingMetaData mappingMetaData = indexMapping.get(MapperService.SINGLE_MAPPING_NAME);
        Map<String, Object> mapping = mappingMetaData.getSourceAsMap();
        String policyName = ObjectPath.eval(MAPPING_POLICY_FIELD_PATH, mapping);
        // Check if index has a corresponding policy
        if (policyName == null || policies.containsKey(policyName) == false) {
            // No corresponding policy. Index should be marked for removal.
            return true;
        }
        // Check if index is currently linked to an alias
        final String aliasName = EnrichPolicy.getBaseName(policyName);
        boolean hasAlias = getIndexResponse.aliases()
            .get(indexName)
            .stream()
            .anyMatch((aliasMetaData -> aliasMetaData.getAlias().equals(aliasName)));
        // Index is not currently published to the enrich alias. Should be marked for removal.
        return hasAlias == false;
    }

    private void deleteIndices(String[] removeIndices) {
        if (removeIndices.length != 0) {
            DeleteIndexRequest deleteIndices = new DeleteIndexRequest()
                .indices(removeIndices)
                .indicesOptions(IGNORE_UNAVAILABLE);
            client.admin().indices().delete(deleteIndices, new ActionListener<>() {
                @Override
                public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                    logger.debug("Completed deletion of stale enrich indices [{}]", () -> Arrays.toString(removeIndices));
                }

                @Override
                public void onFailure(Exception e) {
                    logger.error(() -> "Enrich maintenance task could not delete abandoned enrich indices [" +
                        Arrays.toString(removeIndices) + "]", e);
                }
            });
        }
    }
}
