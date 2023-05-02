/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.profiler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.gateway.GatewayService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.core.ClientHelper;

import java.io.Closeable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.elasticsearch.core.Strings.format;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;

/**
 * Creates all indices that are required for using Elastic Universal Profiling.
 */
public class ProfilingIndexManager implements ClusterStateListener, Closeable {
    private static final Logger logger = LogManager.getLogger(ProfilingIndexManager.class);
    private static final Map<String, String> INDICES_AND_ALIASES;

    static {
        String versionSuffix = "-v" + ProfilingIndexTemplateRegistry.INDEX_TEMPLATE_VERSION;

        Map<String, String> indicesAndAliases = new HashMap<>();
        // TODO: Define behavior on upgrade (delete, reindex, ...), to be done after 8.9.0
        // TODO: This index will be gone with the 8.9 release. Don't bother to implement versioning support.
        indicesAndAliases.put(".profiling-ilm-lock", null);
        indicesAndAliases.put(".profiling-returnpads-private" + versionSuffix, "profiling-returnpads-private");
        indicesAndAliases.put(".profiling-sq-executables" + versionSuffix, "profiling-sq-executables");
        indicesAndAliases.put(".profiling-sq-leafframes" + versionSuffix, "profiling-sq-leafframes");
        indicesAndAliases.put(".profiling-symbols" + versionSuffix, "profiling-symbols");
        indicesAndAliases.put(".profiling-symbols-private" + versionSuffix, "profiling-symbols-private");
        // TODO: Update these to the new K/V strategy after all readers have been adjusted
        String[] kvIndices = new String[] { "profiling-executables", "profiling-stackframes", "profiling-stacktraces" };
        for (String idx : kvIndices) {
            indicesAndAliases.put(idx + "-000001", idx);
            indicesAndAliases.put(idx + "-000002", idx + "-next");
        }
        INDICES_AND_ALIASES = Collections.unmodifiableMap(indicesAndAliases);
    }

    private final ThreadPool threadPool;
    private final Client client;
    private final ClusterService clusterService;
    private final ConcurrentMap<String, AtomicBoolean> indexCreationInProgress = new ConcurrentHashMap<>();

    public ProfilingIndexManager(ThreadPool threadPool, Client client, ClusterService clusterService) {
        this.threadPool = threadPool;
        this.client = client;
        this.clusterService = clusterService;
    }

    public void initialize() {
        clusterService.addListener(this);
    }

    @Override
    public void close() {
        clusterService.removeListener(this);
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        // wait for the cluster state to be recovered
        if (event.state().blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK)) {
            return;
        }

        // If this node is not a master node, exit.
        if (event.state().nodes().isLocalNodeElectedMaster() == false) {
            return;
        }

        if (event.state().nodes().getMaxNodeVersion().after(event.state().nodes().getSmallestNonClientNodeVersion())) {
            logger.debug("Skipping up-to-date check as cluster has mixed versions");
            return;
        }

        // ensure that index templates are present
        if (ProfilingIndexTemplateRegistry.isAllTemplatesCreated(event.state()) == false) {
            logger.trace("Skipping index creation; not all templates are present yet");
            return;
        }

        addIndicesIfMissing(event.state());
    }

    private void addIndicesIfMissing(ClusterState state) {
        Optional<Map<String, IndexMetadata>> maybeMeta = Optional.ofNullable(state.metadata().indices());
        for (Map.Entry<String, String> idxAlias : INDICES_AND_ALIASES.entrySet()) {
            String index = idxAlias.getKey();
            String alias = idxAlias.getValue();
            final AtomicBoolean creationCheck = indexCreationInProgress.computeIfAbsent(index, key -> new AtomicBoolean(false));
            if (creationCheck.compareAndSet(false, true)) {
                final boolean indexNeedsToBeCreated = maybeMeta.flatMap(idxMeta -> Optional.ofNullable(idxMeta.get(index)))
                    .isPresent() == false;
                if (indexNeedsToBeCreated) {
                    logger.debug("adding index [{}], because it doesn't exist", index);
                    putIndex(index, alias, creationCheck);
                } else {
                    logger.trace("not adding index [{}], because it already exists", index);
                    creationCheck.set(false);
                }
            }
        }
    }

    private void onPutIndexFailure(String index, Exception ex) {
        logger.error(() -> format("error adding index [%s] for [%s]", index, ClientHelper.PROFILING_ORIGIN), ex);
    }

    private void putIndex(final String index, final String alias, final AtomicBoolean creationCheck) {
        final Executor executor = threadPool.generic();
        executor.execute(() -> {
            CreateIndexRequest request = new CreateIndexRequest(index);
            if (alias != null) {
                try {
                    Map<String, Object> sourceAsMap = Map.of("aliases", Map.of(alias, Map.of("is_write_index", true)));
                    request.source(sourceAsMap, LoggingDeprecationHandler.INSTANCE);
                } catch (Exception ex) {
                    creationCheck.set(false);
                    onPutIndexFailure(index, ex);
                }
            }
            request.masterNodeTimeout(TimeValue.timeValueMinutes(1));
            executeAsyncWithOrigin(
                client.threadPool().getThreadContext(),
                ClientHelper.PROFILING_ORIGIN,
                request,
                new ActionListener<CreateIndexResponse>() {
                    @Override
                    public void onResponse(CreateIndexResponse response) {
                        creationCheck.set(false);
                        if (response.isAcknowledged() == false) {
                            logger.error(
                                "error adding index [{}] for [{}], request was not acknowledged",
                                index,
                                ClientHelper.PROFILING_ORIGIN
                            );
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        creationCheck.set(false);
                        onPutIndexFailure(index, e);
                    }
                },
                (req, listener) -> client.admin().indices().create(req, listener)
            );
        });
    }
}
