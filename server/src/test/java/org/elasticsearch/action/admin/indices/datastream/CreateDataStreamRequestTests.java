/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.elasticsearch.action.admin.indices.datastream;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.admin.indices.create.CreateIndexClusterStateUpdateRequest;
import org.elasticsearch.action.admin.indices.datastream.CreateDataStreamAction.Request;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.DataStream;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.metadata.MetadataCreateIndexService;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.test.AbstractWireSerializingTestCase;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

public class CreateDataStreamRequestTests extends AbstractWireSerializingTestCase<Request> {

    private final MetadataCreateIndexService metadataCreateIndexService = new MockMetadataCreateIndexService();

    @Override
    protected Writeable.Reader<Request> instanceReader() {
        return Request::new;
    }

    @Override
    protected Request createTestInstance() {
        Request request = new Request(randomAlphaOfLength(8));
        request.setTimestampFieldName(randomAlphaOfLength(8));
        return request;
    }

    public void testValidateRequest() {
        CreateDataStreamAction.Request req = new CreateDataStreamAction.Request("my-data-stream");
        req.setTimestampFieldName("my-timestamp-field");
        ActionRequestValidationException e = req.validate();
        assertNull(e);
    }

    public void testValidateRequestWithoutTimestampField() {
        CreateDataStreamAction.Request req = new CreateDataStreamAction.Request("my-data-stream");
        ActionRequestValidationException e = req.validate();
        assertNotNull(e);
        assertThat(e.validationErrors().size(), equalTo(1));
        assertThat(e.validationErrors().get(0), containsString("timestamp field name is missing"));
    }

    public void testCreateDataStream() throws Exception {
        final String dataStreamName = "my-data-stream";
        ClusterState cs = ClusterState.builder(new ClusterName("_name")).build();
        CreateDataStreamAction.Request req = new CreateDataStreamAction.Request(dataStreamName);
        ClusterState newState = CreateDataStreamAction.TransportAction.createDataStream(metadataCreateIndexService, cs, req);
        assertThat(newState.metadata().dataStreams().size(), equalTo(1));
        assertThat(newState.metadata().dataStreams().get(dataStreamName).getName(), equalTo(dataStreamName));
        assertThat(newState.metadata().index(dataStreamName + "-000000"), notNullValue());
    }

    public void testCreateDuplicateDataStream() {
        final String dataStreamName = "my-data-stream";
        DataStream existingDataStream = new DataStream(dataStreamName, "timestamp", Collections.emptyList());
        ClusterState cs = ClusterState.builder(new ClusterName("_name"))
            .metadata(Metadata.builder().dataStreams(Map.of(dataStreamName, existingDataStream)).build()).build();
        CreateDataStreamAction.Request req = new CreateDataStreamAction.Request(dataStreamName);

        IllegalArgumentException e = expectThrows(IllegalArgumentException.class,
            () -> CreateDataStreamAction.TransportAction.createDataStream(metadataCreateIndexService, cs, req));
        assertThat(e.getMessage(), containsString("data_stream [" + dataStreamName + "] already exists"));
    }

    public void testCreateDataStreamWithInvalidName() {
        final String dataStreamName = "_My-da#ta- ,stream-";
        ClusterState cs = ClusterState.builder(new ClusterName("_name")).build();
        CreateDataStreamAction.Request req = new CreateDataStreamAction.Request(dataStreamName);
        IllegalArgumentException e = expectThrows(IllegalArgumentException.class,
            () -> CreateDataStreamAction.TransportAction.createDataStream(metadataCreateIndexService, cs, req));
        assertThat(e.getMessage(), containsString("must not contain the following characters"));
    }

    private static class MockMetadataCreateIndexService extends MetadataCreateIndexService {

        MockMetadataCreateIndexService() {
            super(null, null, null, null, null, null, null, null, null, null, false);
        }

        @Override
        public ClusterState applyCreateIndexRequest(ClusterState currentState, CreateIndexClusterStateUpdateRequest request,
                                                    boolean silent) throws Exception {
            Metadata.Builder b = Metadata.builder(currentState.metadata())
                .put(IndexMetadata.builder(request.index())
                    .settings(settings(Version.CURRENT))
                    .numberOfShards(1)
                    .numberOfReplicas(1)
                    .build(), false);
            return ClusterState.builder(currentState).metadata(b.build()).build();
        }
    }
}
