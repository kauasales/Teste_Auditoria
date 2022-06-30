/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.health.metadata;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.ClusterStateTaskConfig;
import org.elasticsearch.cluster.ClusterStateTaskExecutor;
import org.elasticsearch.cluster.ClusterStateTaskListener;
import org.elasticsearch.cluster.NamedDiff;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xcontent.ParseField;

import java.util.List;

import static org.elasticsearch.cluster.routing.allocation.DiskThresholdSettings.CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_MAX_HEADROOM_SETTING;
import static org.elasticsearch.cluster.routing.allocation.DiskThresholdSettings.CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_SETTING;
import static org.elasticsearch.cluster.routing.allocation.DiskThresholdSettings.CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_WATERMARK_SETTING;
import static org.elasticsearch.cluster.routing.allocation.DiskThresholdSettings.CLUSTER_ROUTING_ALLOCATION_HIGH_DISK_WATERMARK_SETTING;
import static org.elasticsearch.cluster.routing.allocation.DiskThresholdSettings.CLUSTER_ROUTING_ALLOCATION_LOW_DISK_WATERMARK_SETTING;
import static org.elasticsearch.health.node.selection.HealthNodeTaskExecutor.ENABLED_SETTING;

/**
 * Keeps the health metadata in the cluster state up to date. It listens to master elections and changes in the disk thresholds.
 */
public class HealthMetadataService {

    private static final Logger logger = LogManager.getLogger(HealthMetadataService.class);

    private final ClusterService clusterService;
    private final ClusterStateListener clusterStateListener;
    private final Settings settings;
    private volatile boolean enabled;

    // Signifies that a node has been elected as master, but it was not able yet to publish its health metadata for
    // other reasons for example not all nodes of the cluster are 8.4.0 or newer
    private volatile boolean readyToPublish = false;
    // Allows us to know if this node is the elected master without checking the cluster state, effectively protecting
    // us from checking the cluster state before the cluster state is initialized
    private volatile boolean isMaster = false;

    private final ClusterStateTaskExecutor<UpsertHealthMetadataTask> taskExecutor = new UpsertHealthMetadataTask.Executor();

    public HealthMetadataService(ClusterService clusterService, Settings settings) {
        this.clusterService = clusterService;
        this.settings = settings;
        this.clusterStateListener = this::updateOnClusterStateChange;
        this.enabled = ENABLED_SETTING.get(settings);
        if (this.enabled) {
            this.clusterService.addListener(clusterStateListener);
        }

        ClusterSettings clusterSettings = clusterService.getClusterSettings();
        clusterSettings.addSettingsUpdateConsumer(
            CLUSTER_ROUTING_ALLOCATION_LOW_DISK_WATERMARK_SETTING,
            value -> updateOnSettingsUpdated(CLUSTER_ROUTING_ALLOCATION_LOW_DISK_WATERMARK_SETTING.getKey(), value)
        );
        clusterSettings.addSettingsUpdateConsumer(
            CLUSTER_ROUTING_ALLOCATION_HIGH_DISK_WATERMARK_SETTING,
            value -> updateOnSettingsUpdated(CLUSTER_ROUTING_ALLOCATION_HIGH_DISK_WATERMARK_SETTING.getKey(), value)
        );
        clusterSettings.addSettingsUpdateConsumer(
            CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_WATERMARK_SETTING,
            value -> updateOnSettingsUpdated(CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_WATERMARK_SETTING.getKey(), value)
        );
        clusterSettings.addSettingsUpdateConsumer(
            CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_SETTING,
            value -> updateOnSettingsUpdated(CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_SETTING.getKey(), value.getStringRep())
        );
        clusterSettings.addSettingsUpdateConsumer(
            CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_MAX_HEADROOM_SETTING,
            value -> updateOnSettingsUpdated(
                CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_MAX_HEADROOM_SETTING.getKey(),
                value.getStringRep()
            )
        );
        clusterService.getClusterSettings().addSettingsUpdateConsumer(ENABLED_SETTING, this::enable);
    }

    private void enable(boolean enabled) {
        this.enabled = enabled;
        if (this.enabled) {
            clusterService.addListener(clusterStateListener);
            resetHealthMetadata("health-node-enabled");
        } else {
            clusterService.removeListener(clusterStateListener);
            readyToPublish = false;
        }
    }

    private void updateOnClusterStateChange(ClusterChangedEvent event) {
        final boolean wasMaster = event.previousState().nodes().isLocalNodeElectedMaster();
        isMaster = event.localNodeMaster();
        if (isMaster && wasMaster == false) {
            readyToPublish = true;
        } else if (isMaster == false) {
            readyToPublish = false;
        }
        // Wait until every node in the cluster is upgraded to 8.4.0 or later
        if (event.state().nodesIfRecovered().getMinNodeVersion().onOrAfter(Version.V_8_4_0)) {
            if (readyToPublish) {
                resetHealthMetadata("health-metadata-update-master-election");
                readyToPublish = false;
            }
        }
    }

    private void updateOnSettingsUpdated(String setting, String value) {
        // We do not use the cluster state to check if this is the master node because the cluster state might not have been initialized
        if (isMaster && enabled) {
            ClusterState clusterState = clusterService.state();
            if (clusterState.nodesIfRecovered().getMinNodeVersion().onOrAfter(Version.V_8_4_0)) {
                var task = UpsertHealthMetadataTask.createUpdateTask(clusterState, setting, value);
                var config = ClusterStateTaskConfig.build(Priority.NORMAL);
                clusterService.submitStateUpdateTask("health-metadata-update", task, config, taskExecutor);
            }
        }
    }

    private void resetHealthMetadata(String source) {
        var task = UpsertHealthMetadataTask.createInsertTask(settings);
        var config = ClusterStateTaskConfig.build(Priority.NORMAL);
        clusterService.submitStateUpdateTask(source, task, config, taskExecutor);
    }

    public static List<NamedXContentRegistry.Entry> getNamedXContentParsers() {
        return List.of(
            new NamedXContentRegistry.Entry(Metadata.Custom.class, new ParseField(HealthMetadata.TYPE), HealthMetadata::fromXContent)
        );
    }

    public static List<NamedWriteableRegistry.Entry> getNamedWriteables() {
        return List.of(
            new NamedWriteableRegistry.Entry(Metadata.Custom.class, HealthMetadata.TYPE, HealthMetadata::new),
            new NamedWriteableRegistry.Entry(NamedDiff.class, HealthMetadata.TYPE, HealthMetadata::readDiffFrom)
        );
    }

    static class UpsertHealthMetadataTask implements ClusterStateTaskListener {

        private final HealthMetadata healthMetadata;

        private UpsertHealthMetadataTask(HealthMetadata healthMetadata) {
            this.healthMetadata = healthMetadata;
        }

        static UpsertHealthMetadataTask createInsertTask(Settings settings) {
            return new UpsertHealthMetadataTask(
                new HealthMetadata(
                    new HealthMetadata.Disk(
                        HealthMetadata.Disk.Threshold.parse(
                            CLUSTER_ROUTING_ALLOCATION_LOW_DISK_WATERMARK_SETTING.get(settings),
                            CLUSTER_ROUTING_ALLOCATION_LOW_DISK_WATERMARK_SETTING.getKey()
                        ),
                        HealthMetadata.Disk.Threshold.parse(
                            CLUSTER_ROUTING_ALLOCATION_HIGH_DISK_WATERMARK_SETTING.get(settings),
                            CLUSTER_ROUTING_ALLOCATION_HIGH_DISK_WATERMARK_SETTING.getKey()
                        ),
                        HealthMetadata.Disk.Threshold.parse(
                            CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_WATERMARK_SETTING.get(settings),
                            CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_WATERMARK_SETTING.getKey()
                        ),
                        new HealthMetadata.Disk.Threshold(CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_SETTING.get(settings)),
                        CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_MAX_HEADROOM_SETTING.get(settings)
                    )
                )
            );
        }

        static UpsertHealthMetadataTask createUpdateTask(ClusterState clusterState, String setting, String value) {
            final HealthMetadata initialHealthMetadata = HealthMetadata.getHealthCustomMetadata(clusterState);
            assert initialHealthMetadata != null : "health metadata should have been initialized";
            HealthMetadata.Disk.Builder builder = HealthMetadata.Disk.newBuilder(initialHealthMetadata.getDiskMetadata());
            if (CLUSTER_ROUTING_ALLOCATION_LOW_DISK_WATERMARK_SETTING.getKey().equals(setting)) {
                builder.lowWatermark(value, setting);
            }
            if (CLUSTER_ROUTING_ALLOCATION_HIGH_DISK_WATERMARK_SETTING.getKey().equals(setting)) {
                builder.highWatermark(value, setting);
            }
            if (CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_WATERMARK_SETTING.getKey().equals(setting)) {
                builder.floodStageWatermark(value, setting);
            }
            if (CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_WATERMARK_SETTING.getKey().equals(setting)) {
                builder.frozenFloodStageWatermark(value, setting);
            }
            if (CLUSTER_ROUTING_ALLOCATION_DISK_FLOOD_STAGE_FROZEN_MAX_HEADROOM_SETTING.getKey().equals(setting)) {
                builder.frozenFloodStageMaxHeadroom(value, setting);
            }
            return new UpsertHealthMetadataTask(new HealthMetadata(builder.build()));
        }

        @Override
        public void clusterStateProcessed(ClusterState oldState, ClusterState newState) {
            assert false : "never called";
        }

        @Override
        public void onFailure(@Nullable Exception e) {
            logger.error("failure during health metadata update", e);
        }

        HealthMetadata execute() {
            return healthMetadata;
        }

        static class Executor implements ClusterStateTaskExecutor<UpsertHealthMetadataTask> {

            @Override
            public ClusterState execute(ClusterState currentState, List<TaskContext<UpsertHealthMetadataTask>> taskContexts)
                throws Exception {
                final HealthMetadata initialHealthMetadata = HealthMetadata.getHealthCustomMetadata(currentState);
                HealthMetadata currentHealthMetadata = initialHealthMetadata;
                for (TaskContext<UpsertHealthMetadataTask> taskContext : taskContexts) {
                    currentHealthMetadata = taskContext.getTask().execute();
                    taskContext.success(() -> {});
                }
                final var finalHealthMetadata = currentHealthMetadata;
                return finalHealthMetadata == initialHealthMetadata
                    ? currentState
                    : currentState.copyAndUpdateMetadata(b -> b.putCustom(HealthMetadata.TYPE, finalHealthMetadata));
            }
        }
    }
}
