/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.search;

import org.elasticsearch.ResourceNotFoundException;
import org.elasticsearch.Version;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.ByteBufferStreamInput;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.NamedWriteableAwareStreamInput;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.xpack.core.search.action.AsyncSearchResponse;
import org.elasticsearch.xpack.core.search.action.GetAsyncSearchAction;
import org.elasticsearch.xpack.core.search.action.PartialSearchResponse;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collections;

import static org.elasticsearch.xpack.search.AsyncSearchHistoryTemplateRegistry.INDEX_TEMPLATE_VERSION;
import static org.elasticsearch.xpack.search.AsyncSearchHistoryTemplateRegistry.ASYNC_SEARCH_HISTORY_TEMPLATE_NAME;

/**
 * A class that encapsulates the logic to store and retrieve {@link AsyncSearchResponse} to/from the async
 * search history index.
 */
class AsyncSearchStoreService {
    static final String ASYNC_SEARCH_HISTORY_ALIAS = ASYNC_SEARCH_HISTORY_TEMPLATE_NAME + "-" + INDEX_TEMPLATE_VERSION;
    static final String RESPONSE_FIELD = "response";

    private final Client client;
    private final NamedWriteableRegistry registry;

    AsyncSearchStoreService(Client client, NamedWriteableRegistry registry) {
        this.client = client;
        this.registry = registry;
    }

    /**
     * Store an empty document in the async search history index that is used
     * as a place-holder for the future response.
     */
    void storeInitialResponse(ActionListener<IndexResponse> next) {
        IndexRequest request = new IndexRequest(ASYNC_SEARCH_HISTORY_ALIAS).source(Collections.emptyMap(), XContentType.JSON);
        client.index(request, next);
    }

    /**
     * Store the final response if the place-holder document is still present (update).
     */
    void storeFinalResponse(AsyncSearchResponse response, ActionListener<UpdateResponse> next) throws IOException {
        AsyncSearchId searchId = AsyncSearchId.decode(response.id());
        UpdateRequest request = new UpdateRequest().index(searchId.getIndexName()).id(searchId.getDocId())
            .doc(Collections.singletonMap(RESPONSE_FIELD, encodeResponse(response)), XContentType.JSON)
            .detectNoop(false);
        client.update(request, next);
    }

    /**
     * Get the final response from the async search history index if present, or delegate a {@link ResourceNotFoundException}
     * failure to the provided listener if not.
     */
    void getResponse(GetAsyncSearchAction.Request orig, AsyncSearchId searchId, ActionListener<AsyncSearchResponse> next) {
        GetRequest request = new GetRequest(searchId.getIndexName())
            .id(searchId.getDocId())
            .storedFields(RESPONSE_FIELD);
        client.get(request, ActionListener.wrap(
            get -> {
                if (get.isExists() == false) {
                    next.onFailure(new ResourceNotFoundException(request.id() + " not found"));
                } else if (get.getFields().containsKey(RESPONSE_FIELD) == false) {
                    next.onResponse(new AsyncSearchResponse(orig.getId(), new PartialSearchResponse(-1), 0, false));
                } else {

                    BytesArray bytesArray = get.getFields().get(RESPONSE_FIELD).getValue();
                    next.onResponse(decodeResponse(bytesArray.array(), registry));
                }
            },
            exc -> next.onFailure(new ResourceNotFoundException(request.id() + " not found"))
        ));
    }

    /**
     * Encode the provided response in a binary form using base64 encoding.
     */
    static String encodeResponse(AsyncSearchResponse response) throws IOException {
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            Version.writeVersion(Version.CURRENT, out);
            response.writeTo(out);
            return Base64.getEncoder().encodeToString(BytesReference.toBytes(out.bytes()));
        }
    }

    /**
     * Decode the provided base-64 bytes into a {@link AsyncSearchResponse}.
     */
    static AsyncSearchResponse decodeResponse(byte[] value, NamedWriteableRegistry registry) throws IOException {
        try (ByteBufferStreamInput buf = new ByteBufferStreamInput(ByteBuffer.wrap(value))) {
            try (StreamInput in = new NamedWriteableAwareStreamInput(buf, registry)) {
                in.setVersion(Version.readVersion(in));
                return new AsyncSearchResponse(in);
            }
        }
    }
}
