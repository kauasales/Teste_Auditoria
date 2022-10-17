/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.relevancesearch.xsearch.action;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.ValidateActions;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.util.CollectionUtils;
import org.elasticsearch.xcontent.XContentParser;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

public class XSearchAction extends ActionType<SearchResponse> {

    public static final XSearchAction INSTANCE = new XSearchAction();

    static final String NAME = "indices:data/read/xsearch";

    private XSearchAction() {
        super(NAME, SearchResponse::new);
    }

    public static class Request extends ActionRequest implements IndicesRequest.Replaceable {

        private String[] indices;

        private final String query;

        private final boolean explain;

        private IndicesOptions indicesOptions = IndicesOptions.strictExpandOpenAndForbidClosedIgnoreThrottled();

        public Request(String[] indices, String query, boolean explain) {
            this.indices = indices;
            this.query = query;
            this.explain = explain;
        }

        public Request(StreamInput in) throws IOException {
            super(in);
            this.indices = in.readStringArray();
            this.query = in.readString();
            this.explain = in.readBoolean();
            this.indicesOptions = IndicesOptions.readIndicesOptions(in);
        }

        public static Request parseRequest(String indexNames, XContentParser bodyParser, boolean explain) throws IOException {

            String[] indices = Strings.splitStringByCommaToArray(indexNames);
            String query = (String) bodyParser.map().get("query");

            return new Request(indices, query, explain);
        }

        @Override
        public ActionRequestValidationException validate() {
            ActionRequestValidationException validationException = null;
            if (Strings.hasText(query) == false) {
                validationException = ValidateActions.addValidationError("no query specified", validationException);
            }
            if (CollectionUtils.isEmpty(indices)) {
                validationException = ValidateActions.addValidationError("no indices specified", validationException);
            }
            for (String index : indices) {
                if (Strings.hasText(index) == false) {
                    validationException = ValidateActions.addValidationError("index name can't be empty", validationException);
                }
            }

            return validationException;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeOptionalStringArray(indices);
            out.writeString(query);
            out.writeBoolean(explain);
            indicesOptions.writeIndicesOptions(out);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            XSearchAction.Request request = (XSearchAction.Request) o;
            return Arrays.equals(indices, request.indices)
                && indicesOptions.equals(request.indicesOptions)
                && query.equals(request.query)
                && explain == request.explain;
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(indicesOptions);
            result = 31 * result + Arrays.hashCode(indices) + Objects.hash(query) + Objects.hash(explain);
            return result;
        }

        @Override
        public String[] indices() {
            return indices;
        }

        public String getQuery() {
            return query;
        }

        public boolean explain() {
            return explain;
        }

        @Override
        public IndicesOptions indicesOptions() {
            return indicesOptions;
        }

        public Request indicesOptions(IndicesOptions indicesOptions) {
            this.indicesOptions = indicesOptions;
            return this;
        }

        @Override
        public boolean includeDataStreams() {
            return false;
        }

        @Override
        public IndicesRequest indices(String... indices) {
            this.indices = indices;
            return this;
        }

    }
}
