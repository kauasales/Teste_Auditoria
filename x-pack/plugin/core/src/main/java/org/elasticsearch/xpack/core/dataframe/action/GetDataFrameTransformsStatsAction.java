/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.dataframe.action;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.Version;
import org.elasticsearch.action.Action;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.TaskOperationFailure;
import org.elasticsearch.action.support.tasks.BaseTasksRequest;
import org.elasticsearch.action.support.tasks.BaseTasksResponse;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.xpack.core.action.util.PageParams;
import org.elasticsearch.xpack.core.dataframe.DataFrameField;
import org.elasticsearch.xpack.core.dataframe.transforms.DataFrameTransformStateAndStats;
import org.elasticsearch.xpack.core.dataframe.utils.ExceptionsHelper;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.elasticsearch.action.ValidateActions.addValidationError;

public class GetDataFrameTransformsStatsAction extends Action<GetDataFrameTransformsStatsAction.Response> {

    public static final GetDataFrameTransformsStatsAction INSTANCE = new GetDataFrameTransformsStatsAction();
    public static final String NAME = "cluster:monitor/data_frame/stats/get";
    public GetDataFrameTransformsStatsAction() {
        super(NAME);
    }

    @Override
    public Response newResponse() {
        throw new UnsupportedOperationException("usage of Streamable is to be replaced by Writeable");
    }

    @Override
    public Writeable.Reader<Response> getResponseReader() {
        return Response::new;
    }

    public static class Request extends BaseTasksRequest<Request> {
        private final String id;
        private PageParams pageParams = PageParams.defaultParams();

        public static final int MAX_SIZE_RETURN = 1000;
        // used internally to expand the queried id expression
        private List<String> expandedIds;

        public Request(String id) {
            if (Strings.isNullOrEmpty(id) || id.equals("*")) {
                this.id = MetaData.ALL;
            } else {
                this.id = id;
            }
            this.expandedIds = Collections.singletonList(id);
        }

        public Request(StreamInput in) throws IOException {
            super(in);
            id = in.readString();
            expandedIds = Collections.unmodifiableList(in.readStringList());
            pageParams = new PageParams(in);
        }

        @Override
        public boolean match(Task task) {
            // Only get tasks that we have expanded to
            return expandedIds.stream()
                .anyMatch(transformId -> task.getDescription().equals(DataFrameField.PERSISTENT_TASK_DESCRIPTION_PREFIX + transformId));
        }

        public String getId() {
            return id;
        }

        public List<String> getExpandedIds() {
            return expandedIds;
        }

        public void setExpandedIds(List<String> expandedIds) {
            this.expandedIds = List.copyOf(expandedIds);
        }

        public final void setPageParams(PageParams pageParams) {
            this.pageParams = Objects.requireNonNull(pageParams);
        }

        public final PageParams getPageParams() {
            return pageParams;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(id);
            out.writeStringCollection(expandedIds);
            pageParams.writeTo(out);
        }

        @Override
        public ActionRequestValidationException validate() {
            ActionRequestValidationException exception = null;
            if (getPageParams() != null && getPageParams().getSize() > MAX_SIZE_RETURN) {
                exception = addValidationError("Param [" + PageParams.SIZE.getPreferredName() +
                    "] has a max acceptable value of [" + MAX_SIZE_RETURN + "]", exception);
            }
            return exception;
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, pageParams);
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
            return Objects.equals(id, other.id) && Objects.equals(pageParams, other.pageParams);
        }
    }

    public static class Response extends BaseTasksResponse implements ToXContentObject {
        private List<DataFrameTransformStateAndStats> transformsStateAndStats;
        private long totalCount;

        public Response(List<DataFrameTransformStateAndStats> transformsStateAndStats) {
            super(Collections.emptyList(), Collections.emptyList());
            this.transformsStateAndStats = ExceptionsHelper.requireNonNull(transformsStateAndStats, "transformsStateAndStats");
            this.totalCount = transformsStateAndStats.size();
        }

        public Response(List<DataFrameTransformStateAndStats> transformsStateAndStats, List<TaskOperationFailure> taskFailures,
                List<? extends ElasticsearchException> nodeFailures) {
            super(taskFailures, nodeFailures);
            this.transformsStateAndStats = ExceptionsHelper.requireNonNull(transformsStateAndStats, "transformsStateAndStats");
            this.totalCount = transformsStateAndStats.size();
        }

        public Response(StreamInput in) throws IOException {
            super(in);
            transformsStateAndStats = in.readList(DataFrameTransformStateAndStats::new);
            if (in.getVersion().onOrAfter(Version.V_7_3_0)) {
                totalCount = in.readLong();
            } else {
                totalCount = transformsStateAndStats.size();
            }
        }

        // Set the total count if it is different than transformsStateAndStats.size()
        public Response setTotalCount(long totalCount) {
            assert totalCount >= transformsStateAndStats.size();
            this.totalCount = totalCount;
            return this;
        }

        public List<DataFrameTransformStateAndStats> getTransformsStateAndStats() {
            return transformsStateAndStats;
        }

        public long getTotalCount() {
            return totalCount;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeList(transformsStateAndStats);
            if (out.getVersion().onOrAfter(Version.V_7_3_0)) {
                out.writeLong(totalCount);
            }
        }

        @Override
        public void readFrom(StreamInput in) {
            throw new UnsupportedOperationException("usage of Streamable is to be replaced by Writeable");
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            toXContentCommon(builder, params);
            builder.field(DataFrameField.COUNT.getPreferredName(), totalCount);
            builder.field(DataFrameField.TRANSFORMS.getPreferredName(), transformsStateAndStats);
            builder.endObject();
            return builder;
        }

        @Override
        public int hashCode() {
            return Objects.hash(transformsStateAndStats, totalCount);
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }

            if (other == null || getClass() != other.getClass()) {
                return false;
            }

            final Response that = (Response) other;
            return Objects.equals(this.transformsStateAndStats, that.transformsStateAndStats) && this.totalCount == that.totalCount;
        }

        @Override
        public final String toString() {
            return Strings.toString(this);
        }
    }
}
