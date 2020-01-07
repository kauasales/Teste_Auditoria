/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.eql.plugin;

import org.apache.lucene.search.TotalHits;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.tasks.TaskId;
import org.elasticsearch.tasks.TaskManager;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.eql.action.EqlSearchAction;
import org.elasticsearch.xpack.eql.action.EqlSearchRequest;
import org.elasticsearch.xpack.eql.action.EqlSearchResponse;

public class TransportEqlSearchAction extends HandledTransportAction<EqlSearchRequest, EqlSearchResponse> {
    private final SecurityContext securityContext;
    private final ClusterService clusterService;
    private final TaskManager taskManager;

    @Inject
    public TransportEqlSearchAction(Settings settings, ClusterService clusterService, TransportService transportService,
                                   ThreadPool threadPool, ActionFilters actionFilters) {
        super(EqlSearchAction.NAME, transportService, actionFilters, EqlSearchRequest::new);

        this.securityContext = XPackSettings.SECURITY_ENABLED.get(settings) ?
            new SecurityContext(settings, threadPool.getThreadContext()) : null;
        this.clusterService = clusterService;
        this.taskManager = transportService.getTaskManager();
    }

    @Override
    protected void doExecute(Task task, EqlSearchRequest request, ActionListener<EqlSearchResponse> listener) {
        if (request.waitForCompletion()) {
            operation(request, listener);
        } else {
            // TODO: This is for the test only - we need to create and return another task here during execution
            listener.onResponse(new EqlSearchResponse(new TaskId(clusterService.localNode().getId(), task.getId())));
        }
    }

    public static void operation(EqlSearchRequest request, ActionListener<EqlSearchResponse> listener) {
        // TODO: implement parsing and querying
        listener.onResponse(createResponse(request));
    }

    static EqlSearchResponse createResponse(EqlSearchRequest request) {
        // Stubbed search response
        // TODO: implement actual search response processing once the parser/executor is in place
        EqlSearchResponse.Events events = new EqlSearchResponse.Events(new SearchHit[]{
            new SearchHit(1, "111", null),
            new SearchHit(2, "222", null),
        });
        EqlSearchResponse.Hits hits = new EqlSearchResponse.Hits(new EqlSearchResponse.Sequences(new EqlSearchResponse.Sequence[]{
            new EqlSearchResponse.Sequence(new String[]{"4021"}, events),
            new EqlSearchResponse.Sequence(new String[]{"2343"}, events)
        }), new TotalHits(0,  TotalHits.Relation.EQUAL_TO));
        return new EqlSearchResponse(hits, 0, false);
    }
}
