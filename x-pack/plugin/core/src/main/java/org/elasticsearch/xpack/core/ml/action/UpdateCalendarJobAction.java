/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.action;

import org.elasticsearch.action.Action;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestBuilder;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.protocol.xpack.ml.utils.ExceptionsHelper;
import org.elasticsearch.xpack.core.ml.calendars.Calendar;

import java.io.IOException;
import java.util.Objects;

public class UpdateCalendarJobAction extends Action<PutCalendarAction.Response> {
    public static final UpdateCalendarJobAction INSTANCE = new UpdateCalendarJobAction();
    public static final String NAME = "cluster:admin/xpack/ml/calendars/jobs/update";

    private UpdateCalendarJobAction() {
        super(NAME);
    }

    @Override
    public PutCalendarAction.Response newResponse() {
        return new PutCalendarAction.Response();
    }

    public static class Request extends ActionRequest {

        private String calendarId;
        private String jobIdsToAddExpression;
        private String jobIdsToRemoveExpression;

        public Request() {
        }

        /**
         * Job id expressions may be a single job, job group or comma separated
         * list of job Ids or groups
         */
        public Request(String calendarId, String jobIdsToAddExpression, String jobIdsToRemoveExpression) {
            this.calendarId = ExceptionsHelper.requireNonNull(calendarId, Calendar.ID.getPreferredName());
            this.jobIdsToAddExpression = jobIdsToAddExpression;
            this.jobIdsToRemoveExpression = jobIdsToRemoveExpression;
        }

        public String getCalendarId() {
            return calendarId;
        }

        public String getJobIdsToAddExpression() {
            return jobIdsToAddExpression;
        }

        public String getJobIdsToRemoveExpression() {
            return jobIdsToRemoveExpression;
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public void readFrom(StreamInput in) throws IOException {
            super.readFrom(in);
            calendarId = in.readString();
            jobIdsToAddExpression = in.readOptionalString();
            jobIdsToRemoveExpression = in.readOptionalString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(calendarId);
            out.writeOptionalString(jobIdsToAddExpression);
            out.writeOptionalString(jobIdsToRemoveExpression);
        }

        @Override
        public int hashCode() {
            return Objects.hash(calendarId, jobIdsToAddExpression, jobIdsToRemoveExpression);
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            Request other = (Request) obj;
            return Objects.equals(calendarId, other.calendarId) && Objects.equals(jobIdsToAddExpression, other.jobIdsToAddExpression)
                    && Objects.equals(jobIdsToRemoveExpression, other.jobIdsToRemoveExpression);
        }
    }

    public static class RequestBuilder extends ActionRequestBuilder<Request, PutCalendarAction.Response> {

        public RequestBuilder(ElasticsearchClient client) {
            super(client, INSTANCE, new Request());
        }
    }
}

