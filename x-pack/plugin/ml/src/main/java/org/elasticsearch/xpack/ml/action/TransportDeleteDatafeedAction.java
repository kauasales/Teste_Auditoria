/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.ml.action;

import org.elasticsearch.ResourceNotFoundException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.action.support.master.AcknowledgedTransportMasterNodeAction;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.persistent.PersistentTasksCustomMetadata;
import org.elasticsearch.persistent.PersistentTasksService;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.ml.MlTasks;
import org.elasticsearch.xpack.core.ml.action.DeleteDatafeedAction;
import org.elasticsearch.xpack.core.ml.action.IsolateDatafeedAction;
import org.elasticsearch.xpack.core.ml.utils.ExceptionsHelper;
import org.elasticsearch.xpack.ml.MlConfigMigrationEligibilityCheck;
import org.elasticsearch.xpack.ml.datafeed.DatafeedManager;

import static org.elasticsearch.xpack.core.ClientHelper.ML_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;

public class TransportDeleteDatafeedAction extends AcknowledgedTransportMasterNodeAction<DeleteDatafeedAction.Request> {

    private final Client client;
    private final DatafeedManager datafeedManager;
    private final PersistentTasksService persistentTasksService;
    private final MlConfigMigrationEligibilityCheck migrationEligibilityCheck;

    @Inject
    public TransportDeleteDatafeedAction(Settings settings, TransportService transportService, ClusterService clusterService,
                                         ThreadPool threadPool, ActionFilters actionFilters,
                                         IndexNameExpressionResolver indexNameExpressionResolver,
                                         Client client, PersistentTasksService persistentTasksService,
                                         DatafeedManager datafeedManager) {
        super(DeleteDatafeedAction.NAME, transportService, clusterService, threadPool, actionFilters,
                DeleteDatafeedAction.Request::new, indexNameExpressionResolver, ThreadPool.Names.SAME);
        this.client = client;
        this.persistentTasksService = persistentTasksService;
        this.migrationEligibilityCheck = new MlConfigMigrationEligibilityCheck(settings, clusterService);
        this.datafeedManager = datafeedManager;
    }

    @Override
    protected void masterOperation(Task task, DeleteDatafeedAction.Request request, ClusterState state,
                                   ActionListener<AcknowledgedResponse> listener) {

        if (migrationEligibilityCheck.datafeedIsEligibleForMigration(request.getDatafeedId(), state)) {
            listener.onFailure(ExceptionsHelper.configHasNotBeenMigrated("delete datafeed", request.getDatafeedId()));
            return;
        }

        if (request.isForce()) {
            forceDeleteDatafeed(request, state, listener);
        } else {
            datafeedManager.deleteDatafeed(request, state, listener);
        }
    }

    private void forceDeleteDatafeed(DeleteDatafeedAction.Request request, ClusterState state,
                                     ActionListener<AcknowledgedResponse> listener) {
        ActionListener<Boolean> finalListener = ActionListener.wrap(
                // use clusterService.state() here so that the updated state without the task is available
                response -> datafeedManager.deleteDatafeed(request, clusterService.state(), listener),
                listener::onFailure
        );

        ActionListener<IsolateDatafeedAction.Response> isolateDatafeedHandler = ActionListener.wrap(
                response -> removeDatafeedTask(request, state, finalListener),
                listener::onFailure
        );

        IsolateDatafeedAction.Request isolateDatafeedRequest = new IsolateDatafeedAction.Request(request.getDatafeedId());
        executeAsyncWithOrigin(client, ML_ORIGIN, IsolateDatafeedAction.INSTANCE, isolateDatafeedRequest, isolateDatafeedHandler);
    }

    private void removeDatafeedTask(DeleteDatafeedAction.Request request, ClusterState state, ActionListener<Boolean> listener) {
        PersistentTasksCustomMetadata tasks = state.getMetadata().custom(PersistentTasksCustomMetadata.TYPE);
        PersistentTasksCustomMetadata.PersistentTask<?> datafeedTask = MlTasks.getDatafeedTask(request.getDatafeedId(), tasks);
        if (datafeedTask == null) {
            listener.onResponse(true);
        } else {
            persistentTasksService.sendRemoveRequest(datafeedTask.getId(),
                    new ActionListener<PersistentTasksCustomMetadata.PersistentTask<?>>() {
                        @Override
                        public void onResponse(PersistentTasksCustomMetadata.PersistentTask<?> persistentTask) {
                            listener.onResponse(Boolean.TRUE);
                        }

                        @Override
                        public void onFailure(Exception e) {
                            if (ExceptionsHelper.unwrapCause(e) instanceof ResourceNotFoundException) {
                                // the task has been removed in between
                                listener.onResponse(true);
                            } else {
                                listener.onFailure(e);
                            }
                        }
                    });
        }
    }

    @Override
    protected ClusterBlockException checkBlock(DeleteDatafeedAction.Request request, ClusterState state) {
        return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
    }
}
