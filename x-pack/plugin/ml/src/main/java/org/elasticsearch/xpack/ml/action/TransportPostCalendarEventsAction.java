/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ml.action;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.ml.MlMetaIndex;
import org.elasticsearch.xpack.core.ml.action.PostCalendarEventsAction;
import org.elasticsearch.xpack.core.ml.calendars.Calendar;
import org.elasticsearch.xpack.core.ml.calendars.ScheduledEvent;
import org.elasticsearch.xpack.core.ml.utils.ExceptionsHelper;
import org.elasticsearch.xpack.ml.job.JobManager;
import org.elasticsearch.xpack.ml.job.persistence.JobResultsProvider;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.elasticsearch.xpack.core.ClientHelper.ML_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;

public class TransportPostCalendarEventsAction extends HandledTransportAction<PostCalendarEventsAction.Request,
        PostCalendarEventsAction.Response> {

    private final Client client;
    private final JobResultsProvider jobResultsProvider;
    private final JobManager jobManager;

    @Inject
    public TransportPostCalendarEventsAction(Settings settings, TransportService transportService,
                                             ActionFilters actionFilters, Client client,
                                             JobResultsProvider jobResultsProvider, JobManager jobManager) {
        super(settings, PostCalendarEventsAction.NAME, transportService, actionFilters,
            PostCalendarEventsAction.Request::new);
        this.client = client;
        this.jobResultsProvider = jobResultsProvider;
        this.jobManager = jobManager;
    }

    @Override
    protected void doExecute(Task task, PostCalendarEventsAction.Request request,
                             ActionListener<PostCalendarEventsAction.Response> listener) {
        List<ScheduledEvent> events = request.getScheduledEvents();

        ActionListener<Calendar> calendarListener = ActionListener.wrap(
                calendar -> {
                    BulkRequestBuilder bulkRequestBuilder = client.prepareBulk();

                    for (ScheduledEvent event: events) {
                        IndexRequest indexRequest = new IndexRequest(MlMetaIndex.INDEX_NAME, MlMetaIndex.TYPE);
                        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
                            indexRequest.source(event.toXContent(builder,
                                    new ToXContent.MapParams(Collections.singletonMap(MlMetaIndex.INCLUDE_TYPE_KEY,
                                            "true"))));
                        } catch (IOException e) {
                            throw new IllegalStateException("Failed to serialise event", e);
                        }
                        bulkRequestBuilder.add(indexRequest);
                    }

                    bulkRequestBuilder.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                    executeAsyncWithOrigin(client, ML_ORIGIN, BulkAction.INSTANCE, bulkRequestBuilder.request(),
                            new ActionListener<BulkResponse>() {
                                @Override
                                public void onResponse(BulkResponse response) {
                                    jobManager.updateProcessOnCalendarChanged(calendar.getJobIds());
                                    listener.onResponse(new PostCalendarEventsAction.Response(events));
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    listener.onFailure(ExceptionsHelper.serverError("Error indexing event", e));
                                }
                            });
                },
                listener::onFailure);

        jobResultsProvider.calendar(request.getCalendarId(), calendarListener);
    }
}
