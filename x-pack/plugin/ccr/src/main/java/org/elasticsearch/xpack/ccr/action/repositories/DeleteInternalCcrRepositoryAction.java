/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.ccr.action.repositories;

import org.elasticsearch.action.Action;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.TransportAction;
import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import java.io.IOException;

public class DeleteInternalCcrRepositoryAction extends Action<DeleteInternalCcrRepositoryRequest,
    DeleteInternalCcrRepositoryAction.DeleteInternalCcrRepositoryResponse, DeleteInternalCcrRepositoryRequestBuilder> {

    public static final DeleteInternalCcrRepositoryAction INSTANCE = new DeleteInternalCcrRepositoryAction();
    public static final String NAME = "cluster:admin/ccr/internal_repository/delete";

    private DeleteInternalCcrRepositoryAction() {
        super(NAME);
    }

    @Override
    public DeleteInternalCcrRepositoryResponse newResponse() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Writeable.Reader<DeleteInternalCcrRepositoryResponse> getResponseReader() {
        return DeleteInternalCcrRepositoryResponse::new;
    }

    @Override
    public DeleteInternalCcrRepositoryRequestBuilder newRequestBuilder(ElasticsearchClient client) {
        return new DeleteInternalCcrRepositoryRequestBuilder(client);
    }

    public static class TransportDeleteInternalRepositoryAction
        extends TransportAction<DeleteInternalCcrRepositoryRequest, DeleteInternalCcrRepositoryResponse> {

        private final RepositoriesService repositoriesService;

        @Inject
        public TransportDeleteInternalRepositoryAction(Settings settings, ThreadPool threadPool, RepositoriesService repositoriesService,
                                                       ActionFilters actionFilters, IndexNameExpressionResolver resolver,
                                                       TransportService transportService) {
            super(settings, NAME, threadPool, actionFilters, resolver, transportService.getTaskManager());
            this.repositoriesService = repositoriesService;
        }

        @Override
        protected void doExecute(DeleteInternalCcrRepositoryRequest request,
                                 ActionListener<DeleteInternalCcrRepositoryResponse> listener) {
            repositoriesService.unregisterInternalRepository(request.getName());
            listener.onResponse(new DeleteInternalCcrRepositoryResponse());
        }
    }

    public static class DeleteInternalCcrRepositoryResponse extends ActionResponse {

        DeleteInternalCcrRepositoryResponse() {
            super();
        }

        DeleteInternalCcrRepositoryResponse(StreamInput streamInput) throws IOException {
            super(streamInput);
        }
    }
}
