/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.inference.trainedmodel;

import org.elasticsearch.common.io.stream.NamedWriteable;
import org.elasticsearch.xpack.core.ml.inference.TrainedModelConfig;
import org.elasticsearch.xpack.core.ml.inference.results.WarningInferenceResults;
import org.elasticsearch.xpack.core.ml.utils.ExceptionsHelper;
import org.elasticsearch.xpack.core.ml.utils.NamedXContentObject;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


public interface InferenceConfigUpdate extends NamedXContentObject, NamedWriteable {
    Set<String> RESERVED_ML_FIELD_NAMES = new HashSet<>(Arrays.asList(
        WarningInferenceResults.WARNING.getPreferredName(),
        TrainedModelConfig.MODEL_ID.getPreferredName()));

    InferenceConfig apply(InferenceConfig originalConfig);

    InferenceConfig toConfig();

    boolean isSupported(InferenceConfig config);

    String getResultsField();

    static void checkFieldUniqueness(String... fieldNames) {
        Set<String> duplicatedFieldNames = new HashSet<>();
        Set<String> currentFieldNames = new HashSet<>(RESERVED_ML_FIELD_NAMES);
        for(String fieldName : fieldNames) {
            if (fieldName == null) {
                continue;
            }
            if (currentFieldNames.contains(fieldName)) {
                duplicatedFieldNames.add(fieldName);
            } else {
                currentFieldNames.add(fieldName);
            }
        }
        if (duplicatedFieldNames.isEmpty() == false) {
            throw ExceptionsHelper.badRequestException("Cannot apply inference config." +
                    " More than one field is configured as {}",
                duplicatedFieldNames);
        }
    }
}
