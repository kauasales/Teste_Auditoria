/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ml.action;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.ml.action.FindFileStructureAction;
import org.elasticsearch.xpack.ml.MachineLearning;
import org.elasticsearch.xpack.ml.filestructurefinder.FileStructureFinder;
import org.elasticsearch.xpack.ml.filestructurefinder.FileStructureFinderManager;

public class TransportFindFileStructureAction
    extends HandledTransportAction<FindFileStructureAction.Request, FindFileStructureAction.Response> {

    @Inject
    public TransportFindFileStructureAction(Settings settings, TransportService transportService, ThreadPool threadPool,
                                            ActionFilters actionFilters, IndexNameExpressionResolver indexNameExpressionResolver) {
        super(settings, FindFileStructureAction.NAME, threadPool, transportService, actionFilters, indexNameExpressionResolver,
            FindFileStructureAction.Request::new);
    }

    @Override
    protected void doExecute(FindFileStructureAction.Request request, ActionListener<FindFileStructureAction.Response> listener) {

        // As determining the file structure might take a while, we run
        // in a different thread to avoid blocking the network thread.
        threadPool.executor(MachineLearning.UTILITY_THREAD_POOL_NAME).execute(() -> {
            try {
                listener.onResponse(buildFileStructureResponse(request));
            } catch (Exception e) {
                listener.onFailure(e);
            }
        });
    }

    private FindFileStructureAction.Response buildFileStructureResponse(FindFileStructureAction.Request request) throws Exception {

        FileStructureFinderManager structureFinderManager = new FileStructureFinderManager();

        FileStructureFinder fileStructureFinder =
            structureFinderManager.findFileStructure(request.getLinesToSample(), request.getSample().streamInput());

        return new FindFileStructureAction.Response(fileStructureFinder.getStructure());
    }
}
