/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.admin.cluster.migration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.master.TransportMasterNodeAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.indices.SystemIndices;
import org.elasticsearch.persistent.PersistentTasksService;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.upgrades.SystemIndexMigrationTaskParams;

import java.util.ArrayList;
import java.util.List;

import static org.elasticsearch.upgrades.SystemIndexMigrationTaskParams.SYSTEM_INDEX_UPGRADE_TASK_NAME;

/**
 * Transport action for post feature upgrade action
 */
public class TransportPostFeatureUpgradeAction extends TransportMasterNodeAction<
    PostFeatureUpgradeRequest,
    PostFeatureUpgradeResponse> {
    private static final Logger logger = LogManager.getLogger(TransportPostFeatureUpgradeAction.class);

    private final SystemIndices systemIndices;
    private final PersistentTasksService persistentTasksService;

    @Inject
    public TransportPostFeatureUpgradeAction(
        TransportService transportService,
        ThreadPool threadPool,
        ActionFilters actionFilters,
        ClusterService clusterService,
        IndexNameExpressionResolver indexNameExpressionResolver,
        SystemIndices systemIndices,
        PersistentTasksService persistentTasksService
    ) {
        super(
            PostFeatureUpgradeAction.NAME,
            transportService,
            clusterService,
            threadPool,
            actionFilters,
            PostFeatureUpgradeRequest::new,
            indexNameExpressionResolver,
            PostFeatureUpgradeResponse::new,
            ThreadPool.Names.SAME
        );
        this.systemIndices = systemIndices;
        this.persistentTasksService = persistentTasksService;
    }

    @Override
    protected void masterOperation(
        Task task,
        PostFeatureUpgradeRequest request,
        ClusterState state,
        ActionListener<PostFeatureUpgradeResponse> listener
    ) throws Exception {
        List<PostFeatureUpgradeResponse.Feature> features = new ArrayList<>();
        features.add(new PostFeatureUpgradeResponse.Feature("security"));

        persistentTasksService.sendStartRequest(
            SYSTEM_INDEX_UPGRADE_TASK_NAME,
            SYSTEM_INDEX_UPGRADE_TASK_NAME,
            new SystemIndexMigrationTaskParams(),
            ActionListener.wrap(startedTask -> {
                // GWB> Fix this call!!!
                listener.onResponse(new PostFeatureUpgradeResponse(true, null, null, null));
            }, ex -> {
                logger.error("failed to start system index upgrade task", ex);

                listener.onResponse(new PostFeatureUpgradeResponse(false, null, null, new ElasticsearchException(ex)));
            })
        );
        listener.onResponse(new PostFeatureUpgradeResponse(
            // TODO: implement operation for this action
            true, features, null, null));
    }

    @Override
    protected ClusterBlockException checkBlock(PostFeatureUpgradeRequest request, ClusterState state) {
        return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
    }
}
