/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.inference.preprocessing;

import org.elasticsearch.common.io.stream.NamedWriteable;
import org.elasticsearch.xpack.core.ml.utils.NamedXContentObject;

import java.util.Map;

/**
 * Describes a pre-processor for a defined machine learning model
 * This processor should take a set of fields and return the modified set of fields.
 */
public interface PreProcessor extends NamedXContentObject, NamedWriteable {

    /**
     * Process the give fields and their values and return the modified map.
     *
     * NOTE: The passed map object COULD be mutated
     * @param fields The fields and their values to process
     * @return The modified map where the desired field(s) is processed
     */
    Map<String, Object> process(Map<String, Object> fields);
}
