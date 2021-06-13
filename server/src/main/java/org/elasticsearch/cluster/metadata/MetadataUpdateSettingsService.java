/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.metadata;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.settings.put.UpdateSettingsClusterStateUpdateRequest;
import org.elasticsearch.action.admin.indices.upgrade.post.UpgradeSettingsClusterStateUpdateRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.cluster.AckedClusterStateUpdateTask;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlock;
import org.elasticsearch.cluster.block.ClusterBlocks;
import org.elasticsearch.cluster.routing.RoutingTable;
import org.elasticsearch.cluster.routing.allocation.AllocationService;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Priority;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.regex.Regex;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.indices.IndicesService;
import org.elasticsearch.indices.ShardLimitValidator;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.elasticsearch.action.support.ContextPreservingActionListener.wrapPreservingContext;
import static org.elasticsearch.index.IndexSettings.same;

/**
 * Service responsible for submitting update index settings requests
 */
public class MetadataUpdateSettingsService {
    private static final Logger logger = LogManager.getLogger(MetadataUpdateSettingsService.class);

    private final ClusterService clusterService;

    private final AllocationService allocationService;

    private final IndexScopedSettings indexScopedSettings;
    private final IndicesService indicesService;
    private final ShardLimitValidator shardLimitValidator;
    private final ThreadPool threadPool;

    @Inject
    public MetadataUpdateSettingsService(ClusterService clusterService, AllocationService allocationService,
                                         IndexScopedSettings indexScopedSettings, IndicesService indicesService,
                                         ShardLimitValidator shardLimitValidator, ThreadPool threadPool) {
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.allocationService = allocationService;
        this.indexScopedSettings = indexScopedSettings;
        this.indicesService = indicesService;
        this.shardLimitValidator = shardLimitValidator;
    }

    public void updateSettings(final UpdateSettingsClusterStateUpdateRequest request,
                               final ActionListener<AcknowledgedResponse> listener) {
        final Settings normalizedSettings =
            Settings.builder().put(request.settings()).normalizePrefix(IndexMetadata.INDEX_SETTING_PREFIX).build();
        Settings.Builder settingsForClosedIndices = Settings.builder();
        Settings.Builder settingsForOpenIndices = Settings.builder();
        final Set<String> skippedSettings = new HashSet<>();

        indexScopedSettings.validate(
                normalizedSettings.filter(s -> Regex.isSimpleMatchPattern(s) == false), // don't validate wildcards
                false, // don't validate values here we check it below never allow to change the number of shards
                true); // validate internal or private index settings
        for (String key : normalizedSettings.keySet()) {
            Setting setting = indexScopedSettings.get(key);
            boolean isWildcard = setting == null && Regex.isSimpleMatchPattern(key);
            assert setting != null // we already validated the normalized settings
                || (isWildcard && normalizedSettings.hasValue(key) == false)
                : "unknown setting: " + key + " isWildcard: " + isWildcard + " hasValue: " + normalizedSettings.hasValue(key);
            settingsForClosedIndices.copy(key, normalizedSettings);
            if (isWildcard || setting.isDynamic()) {
                settingsForOpenIndices.copy(key, normalizedSettings);
            } else {
                skippedSettings.add(key);
            }
        }
        final Settings closedSettings = settingsForClosedIndices.build();
        final Settings openSettings = settingsForOpenIndices.build();
        final boolean preserveExisting = request.isPreserveExisting();

        clusterService.submitStateUpdateTask("update-settings " + Arrays.toString(request.indices()),
                new AckedClusterStateUpdateTask(Priority.URGENT, request,
                    wrapPreservingContext(listener, threadPool.getThreadContext())) {

            @Override
            public ClusterState execute(ClusterState currentState) {

                RoutingTable.Builder routingTableBuilder = RoutingTable.builder(currentState.routingTable());
                Metadata.Builder metadataBuilder = Metadata.builder(currentState.metadata());

                // allow to change any settings to a close index, and only allow dynamic settings to be changed
                // on an open index
                Set<Index> openIndices = new HashSet<>();
                Set<Index> closeIndices = new HashSet<>();
                final String[] actualIndices = new String[request.indices().length];
                for (int i = 0; i < request.indices().length; i++) {
                    Index index = request.indices()[i];
                    actualIndices[i] = index.getName();
                    final IndexMetadata metadata = currentState.metadata().getIndexSafe(index);
                    if (metadata.getState() == IndexMetadata.State.OPEN) {
                        openIndices.add(index);
                    } else {
                        closeIndices.add(index);
                    }
                }

                if (skippedSettings.isEmpty() == false && openIndices.isEmpty() == false) {
                    throw new IllegalArgumentException(String.format(Locale.ROOT,
                            "Can't update non dynamic settings [%s] for open indices %s", skippedSettings, openIndices));
                }

                if (IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING.exists(openSettings)) {
                    final int updatedNumberOfReplicas = IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING.get(openSettings);
                    if (preserveExisting == false) {
                        // Verify that this won't take us over the cluster shard limit.
                        shardLimitValidator.validateShardLimitOnReplicaUpdate(currentState, request.indices(), updatedNumberOfReplicas);

                        /*
                         * We do not update the in-sync allocation IDs as they will be removed upon the first index operation which makes
                         * these copies stale.
                         *
                         * TODO: should we update the in-sync allocation IDs once the data is deleted by the node?
                         */
                        routingTableBuilder.updateNumberOfReplicas(updatedNumberOfReplicas, actualIndices);
                        metadataBuilder.updateNumberOfReplicas(updatedNumberOfReplicas, actualIndices);
                        logger.info("updating number_of_replicas to [{}] for indices {}", updatedNumberOfReplicas, actualIndices);
                    }
                }

                if (openIndices.isEmpty() == false) {
                    for (Index index : openIndices) {
                        IndexMetadata indexMetadata = metadataBuilder.getSafe(index);
                        Settings.Builder updates = Settings.builder();
                        Settings.Builder indexSettings = Settings.builder().put(indexMetadata.getSettings());
                        if (indexScopedSettings.updateDynamicSettings(openSettings, indexSettings, updates, index.getName())) {
                            if (preserveExisting) {
                                indexSettings.put(indexMetadata.getSettings());
                            }
                            /*
                             * The setting index.number_of_replicas is special; we require that this setting has a value in the index. When
                             * creating the index, we ensure this by explicitly providing a value for the setting to the default (one) if
                             * there is a not value provided on the source of the index creation. A user can update this setting though,
                             * including updating it to null, indicating that they want to use the default value. In this case, we again
                             * have to provide an explicit value for the setting to the default (one).
                             */
                            if (IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING.exists(indexSettings) == false) {
                                indexSettings.put(
                                    IndexMetadata.SETTING_NUMBER_OF_REPLICAS,
                                    IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING.get(Settings.EMPTY));
                            }
                            Settings finalSettings = indexSettings.build();
                            indexScopedSettings.validate(
                                finalSettings.filter(k -> indexScopedSettings.isPrivateSetting(k) == false), true);
                            metadataBuilder.put(IndexMetadata.builder(indexMetadata).settings(finalSettings));
                        }
                    }
                }

                if (closeIndices.isEmpty() == false) {
                    for (Index index : closeIndices) {
                        IndexMetadata indexMetadata = metadataBuilder.getSafe(index);
                        Settings.Builder updates = Settings.builder();
                        Settings.Builder indexSettings = Settings.builder().put(indexMetadata.getSettings());
                        if (indexScopedSettings.updateSettings(closedSettings, indexSettings, updates, index.getName())) {
                            if (preserveExisting) {
                                indexSettings.put(indexMetadata.getSettings());
                            }
                            /*
                             * The setting index.number_of_replicas is special; we require that this setting has a value in the index. When
                             * creating the index, we ensure this by explicitly providing a value for the setting to the default (one) if
                             * there is a not value provided on the source of the index creation. A user can update this setting though,
                             * including updating it to null, indicating that they want to use the default value. In this case, we again
                             * have to provide an explicit value for the setting to the default (one).
                             */
                            if (IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING.exists(indexSettings) == false) {
                                indexSettings.put(
                                    IndexMetadata.SETTING_NUMBER_OF_REPLICAS,
                                    IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING.get(Settings.EMPTY));
                            }
                            Settings finalSettings = indexSettings.build();
                            indexScopedSettings.validate(
                                finalSettings.filter(k -> indexScopedSettings.isPrivateSetting(k) == false), true);
                            metadataBuilder.put(IndexMetadata.builder(indexMetadata).settings(finalSettings));
                        }
                    }
                }

                if (IndexSettings.INDEX_TRANSLOG_RETENTION_AGE_SETTING.exists(normalizedSettings) ||
                    IndexSettings.INDEX_TRANSLOG_RETENTION_SIZE_SETTING.exists(normalizedSettings)) {
                    for (String index : actualIndices) {
                        MetadataCreateIndexService.validateTranslogRetentionSettings(metadataBuilder.get(index).getSettings());
                    }
                }
                boolean changed = false;
                // increment settings versions
                for (final String index : actualIndices) {
                    if (same(currentState.metadata().index(index).getSettings(), metadataBuilder.get(index).getSettings()) == false) {
                        changed = true;
                        final IndexMetadata.Builder builder = IndexMetadata.builder(metadataBuilder.get(index));
                        builder.settingsVersion(1 + builder.settingsVersion());
                        metadataBuilder.put(builder);
                    }
                }

                final ClusterBlocks.Builder blocks = ClusterBlocks.builder().blocks(currentState.blocks());
                for (IndexMetadata.APIBlock block : IndexMetadata.APIBlock.values()) {
                    changed |= maybeUpdateClusterBlock(actualIndices, blocks, block.block, block.setting, openSettings);
                }

                if (changed == false) {
                    return currentState;
                }

                ClusterState updatedState = ClusterState.builder(currentState).metadata(metadataBuilder)
                    .routingTable(routingTableBuilder.build()).blocks(blocks).build();

                // now, reroute in case things change that require it (like number of replicas)
                updatedState = allocationService.reroute(updatedState, "settings update");
                try {
                    for (Index index : openIndices) {
                        final IndexMetadata currentMetadata = currentState.getMetadata().getIndexSafe(index);
                        final IndexMetadata updatedMetadata = updatedState.metadata().getIndexSafe(index);
                        indicesService.verifyIndexMetadata(currentMetadata, updatedMetadata);
                    }
                    for (Index index : closeIndices) {
                        final IndexMetadata currentMetadata = currentState.getMetadata().getIndexSafe(index);
                        final IndexMetadata updatedMetadata = updatedState.metadata().getIndexSafe(index);
                        // Verifies that the current index settings can be updated with the updated dynamic settings.
                        indicesService.verifyIndexMetadata(currentMetadata, updatedMetadata);
                        // Now check that we can create the index with the updated settings (dynamic and non-dynamic).
                        // This step is mandatory since we allow to update non-dynamic settings on closed indices.
                        indicesService.verifyIndexMetadata(updatedMetadata, updatedMetadata);
                    }
                } catch (IOException ex) {
                    throw ExceptionsHelper.convertToElastic(ex);
                }
                return updatedState;
            }
        });
    }

    /**
     * Updates the cluster block only iff the setting exists in the given settings
     */
    private static boolean maybeUpdateClusterBlock(String[] actualIndices, ClusterBlocks.Builder blocks, ClusterBlock block,
                                                Setting<Boolean> setting, Settings openSettings) {
        boolean changed = false;
        if (setting.exists(openSettings)) {
            final boolean updateBlock = setting.get(openSettings);
            for (String index : actualIndices) {
                if (updateBlock) {
                    if (blocks.hasIndexBlock(index, block) == false) {
                        blocks.addIndexBlock(index, block);
                        changed = true;
                    }
                } else {
                    if (blocks.hasIndexBlock(index, block)) {
                        blocks.removeIndexBlock(index, block);
                        changed = true;
                    }
                }
            }
        }
        return changed;
    }


    public void upgradeIndexSettings(final UpgradeSettingsClusterStateUpdateRequest request,
                                     final ActionListener<AcknowledgedResponse> listener) {
        clusterService.submitStateUpdateTask("update-index-compatibility-versions",
            new AckedClusterStateUpdateTask(Priority.URGENT, request, wrapPreservingContext(listener, threadPool.getThreadContext())) {

            @Override
            public ClusterState execute(ClusterState currentState) {
                Metadata.Builder metadataBuilder = Metadata.builder(currentState.metadata());
                for (Map.Entry<String, Tuple<Version, String>> entry : request.versions().entrySet()) {
                    String index = entry.getKey();
                    IndexMetadata indexMetadata = metadataBuilder.get(index);
                    if (indexMetadata != null) {
                        if (Version.CURRENT.equals(indexMetadata.getCreationVersion()) == false) {
                            // no reason to pollute the settings, we didn't really upgrade anything
                            metadataBuilder.put(
                                    IndexMetadata
                                            .builder(indexMetadata)
                                            .settings(
                                                    Settings
                                                            .builder()
                                                            .put(indexMetadata.getSettings())
                                                            .put(IndexMetadata.SETTING_VERSION_UPGRADED, entry.getValue().v1()))
                                            .settingsVersion(1 + indexMetadata.getSettingsVersion()));
                        }
                    }
                }
                return ClusterState.builder(currentState).metadata(metadataBuilder).build();
            }
        });
    }
}
