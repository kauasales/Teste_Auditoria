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

package org.elasticsearch.indices.recovery;

import org.apache.lucene.index.IndexFileNames;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.InputStreamStreamInput;
import org.elasticsearch.common.io.stream.OutputStreamStreamOutput;
import org.elasticsearch.common.transport.LocalTransportAddress;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.store.Store;
import org.elasticsearch.index.store.StoreFileMetaData;
import org.elasticsearch.test.ElasticsearchTestCase;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.elasticsearch.test.VersionUtils.randomVersion;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

/**
 */
public class StartRecoveryRequestTest extends ElasticsearchTestCase {

    @Test
    public void testSerialization() throws Exception {
        Version targetNodeVersion = randomVersion(random());
        StartRecoveryRequest outRequest = new StartRecoveryRequest(
                new ShardId("test", 0),
                new DiscoveryNode("a", new LocalTransportAddress("1"), targetNodeVersion),
                new DiscoveryNode("b", new LocalTransportAddress("1"), targetNodeVersion),
                true,
                Store.MetadataSnapshot.EMPTY,
                RecoveryState.Type.RELOCATION,
                1l

        );
        ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
        OutputStreamStreamOutput out = new OutputStreamStreamOutput(outBuffer);
        out.setVersion(targetNodeVersion);
        outRequest.writeTo(out);

        ByteArrayInputStream inBuffer = new ByteArrayInputStream(outBuffer.toByteArray());
        InputStreamStreamInput in = new InputStreamStreamInput(inBuffer);
        in.setVersion(targetNodeVersion);
        StartRecoveryRequest inRequest = new StartRecoveryRequest();
        inRequest.readFrom(in);

        assertThat(outRequest.shardId(), equalTo(inRequest.shardId()));
        assertThat(outRequest.sourceNode(), equalTo(inRequest.sourceNode()));
        assertThat(outRequest.targetNode(), equalTo(inRequest.targetNode()));
        assertThat(outRequest.markAsRelocated(), equalTo(inRequest.markAsRelocated()));
        assertThat(outRequest.metadataSnapshot().asMap(), equalTo(inRequest.metadataSnapshot().asMap()));
        assertThat(outRequest.recoveryId(), equalTo(inRequest.recoveryId()));
        assertThat(outRequest.recoveryType(), equalTo(inRequest.recoveryType()));
    }


    // TODO: where should this test be?
    @Test
    public void testMetadataSnapshotStreaming() throws Exception {

        StoreFileMetaData storeFileMetaData1 = new StoreFileMetaData("segments", 1);
        StoreFileMetaData storeFileMetaData2 = new StoreFileMetaData("no_segments", 1);
        Map<String, StoreFileMetaData> storeFileMetaDataMap = new HashMap<>();
        storeFileMetaDataMap.put(storeFileMetaData1.name(), storeFileMetaData1);
        storeFileMetaDataMap.put(storeFileMetaData2.name(), storeFileMetaData2);
        Map<String, String> commitUserData = new HashMap<>();
        commitUserData.put("userdata_1", randomBoolean() ? "test" : null);
        commitUserData.put("userdata_2", randomBoolean() ? "test" : null);
        Store.MetadataSnapshot outMetadataSnapshot = new Store.MetadataSnapshot(storeFileMetaDataMap, commitUserData);
        Version targetNodeVersion = randomVersion(random());

        ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
        OutputStreamStreamOutput out = new OutputStreamStreamOutput(outBuffer);
        out.setVersion(targetNodeVersion);
        outMetadataSnapshot.writeTo(out);

        ByteArrayInputStream inBuffer = new ByteArrayInputStream(outBuffer.toByteArray());
        InputStreamStreamInput in = new InputStreamStreamInput(inBuffer);
        in.setVersion(targetNodeVersion);
        Store.MetadataSnapshot inMetadataSnapshot = Store.MetadataSnapshot.read(in);
        Map<String, StoreFileMetaData> origEntries = outMetadataSnapshot.asMap();
        for (Map.Entry<String, StoreFileMetaData> entry : inMetadataSnapshot.asMap().entrySet()) {
            assertThat(entry.getValue().name(), equalTo(origEntries.remove(entry.getKey()).name()));
        }
        assertThat(origEntries.size(), equalTo(0));
        assertThat(inMetadataSnapshot.getCommitUserData(), equalTo(outMetadataSnapshot.getCommitUserData()));
    }

}
