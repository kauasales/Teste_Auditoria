/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.inference.services.elser;

import org.elasticsearch.TransportVersion;
import org.elasticsearch.TransportVersions;
import org.elasticsearch.common.ValidationException;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.xpack.core.ml.inference.assignment.AdaptiveAllocationsSettings;
import org.elasticsearch.xpack.inference.services.elasticsearch.ElasticsearchInternalServiceSettings;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import static org.elasticsearch.xpack.inference.services.elser.ElserInternalService.VALID_ELSER_MODEL_IDS;

public class ElserInternalServiceSettings extends ElasticsearchInternalServiceSettings {

    public static final String NAME = "elser_mlnode_service_settings";

    public static ElasticsearchInternalServiceSettings.Builder fromRequestMap(Map<String, Object> map) {
        ValidationException validationException = new ValidationException();
        Integer numAllocations = ServiceUtils.removeAsType(map, NUM_ALLOCATIONS, Integer.class);
        Integer numThreads = ServiceUtils.removeAsType(map, NUM_THREADS, Integer.class);

        validateParameters(numAllocations, validationException, numThreads);

        String modelId = ServiceUtils.removeAsType(map, MODEL_ID, String.class);
        if (modelId != null && ElserModels.isValidModel(modelId) == false) {
            validationException.addValidationError("unknown ELSER model id [" + modelId + "]. Valid models are " + Arrays.toString(ElserModels.VALID_ELSER_MODEL_IDS.toArray()));
        }
      
        if (validationException.validationErrors().isEmpty() == false) {
            throw validationException;
        }

        var builder = new InternalServiceSettings.Builder() {
            @Override
            public ElserInternalServiceSettings build() {
                return new ElserInternalServiceSettings(getNumAllocations(), getNumThreads(), getModelId());
            }
        };
        builder.setNumAllocations(numAllocations);
        builder.setNumThreads(numThreads);
        builder.setModelId(modelId);
        return builder;
    }

    public ElserInternalServiceSettings(ElasticsearchInternalServiceSettings other) {
        super(other);
    }

    public ElserInternalServiceSettings(
        Integer numAllocations,
        int numThreads,
        String modelId,
        AdaptiveAllocationsSettings adaptiveAllocationsSettings
    ) {
        this(new ElasticsearchInternalServiceSettings(numAllocations, numThreads, modelId, adaptiveAllocationsSettings));
    }

    public ElserInternalServiceSettings(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public String getWriteableName() {
        return ElserInternalServiceSettings.NAME;
    }

    @Override
    public TransportVersion getMinimalSupportedVersion() {
        return TransportVersions.V_8_11_X;
    }
}
