/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ccr.action;

import org.elasticsearch.ElasticsearchStatusException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.state.ClusterStateRequest;
import org.elasticsearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.elasticsearch.action.admin.indices.mapping.put.MappingRequestValidator;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.MappingMetaData;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.Index;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.xpack.ccr.CcrSettings;

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public final class CcrRequests {

    private CcrRequests() {}

    public static ClusterStateRequest metaDataRequest(String leaderIndex) {
        ClusterStateRequest clusterStateRequest = new ClusterStateRequest();
        clusterStateRequest.clear();
        clusterStateRequest.metaData(true);
        clusterStateRequest.indices(leaderIndex);
        return clusterStateRequest;
    }

    public static PutMappingRequest putMappingRequest(String followerIndex, MappingMetaData mappingMetaData) {
        PutMappingRequest putMappingRequest = new PutMappingRequest(followerIndex);
        putMappingRequest.origin("ccr");
        putMappingRequest.type(mappingMetaData.type());
        putMappingRequest.source(mappingMetaData.source().string(), XContentType.JSON);
        return putMappingRequest;
    }

    /**
     * Gets an {@link IndexMetaData} of the given index. The mapping version and metadata version of the responded {@link IndexMetaData}
     * must be at least the provided {@code mappingVersion} and {@code metadataVersion} respectively.
     */
    public static void getIndexMetadata(Client client, Index index, long mappingVersion, long metadataVersion,
                                        Supplier<TimeValue> timeoutSupplier, ActionListener<IndexMetaData> listener) {
        final ClusterStateRequest request = CcrRequests.metaDataRequest(index.getName());
        if (metadataVersion > 0) {
            request.waitForMetaDataVersion(metadataVersion).waitForTimeout(timeoutSupplier.get());
        }
        client.admin().cluster().state(request, ActionListener.wrap(
            response -> {
                if (response.getState() == null) {
                    assert metadataVersion > 0 : metadataVersion;
                    throw new IllegalStateException("timeout to get cluster state with" +
                        " metadata version [" + metadataVersion + "], mapping version [" + mappingVersion + "]");
                }
                final MetaData metaData = response.getState().metaData();
                final IndexMetaData indexMetaData = metaData.getIndexSafe(index);
                if (indexMetaData.getMappingVersion() >= mappingVersion) {
                    listener.onResponse(indexMetaData);
                    return;
                }
                if (timeoutSupplier.get().nanos() < 0) {
                    throw new IllegalStateException("timeout to get cluster state with mapping version [" + mappingVersion + "]");
                }
                // ask for the next version.
                getIndexMetadata(client, index, mappingVersion, metaData.version() + 1, timeoutSupplier, listener);
            },
            listener::onFailure
        ));
    }

    public static final MappingRequestValidator CCR_PUT_MAPPING_REQUEST_VALIDATOR = (request, state, indices) -> {
        if (request.origin() == null) {
            return null; // a put-mapping-request on old versions does not have origin.
        }
        final List<Index> followingIndices = Arrays.stream(indices)
            .filter(index -> {
                final IndexMetaData indexMetaData = state.metaData().index(index);
                return indexMetaData != null && CcrSettings.CCR_FOLLOWING_INDEX_SETTING.get(indexMetaData.getSettings());
            }).collect(Collectors.toList());
        if (followingIndices.isEmpty() == false && "ccr".equals(request.origin()) == false) {
            final String errorMessage = "can't put mapping to the following indices "
                + "[" + followingIndices.stream().map(Index::getName).collect(Collectors.joining(", ")) + "]; "
                + "the mapping of the following indices are self-replicated from its leader indices";
            return new ElasticsearchStatusException(errorMessage, RestStatus.FORBIDDEN);
        }
        return null;
    };
}
