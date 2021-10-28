/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.ml.inference.preprocessing;

import org.apache.lucene.util.Accountable;
import org.elasticsearch.common.io.stream.NamedWriteable;
import org.elasticsearch.xpack.core.ml.utils.NamedXContentObject;

import java.util.List;
import java.util.Map;

/**
 * Describes a pre-processor for a defined machine learning model
 * This processor should take a set of fields and return the modified set of fields.
 */
public interface PreProcessor extends NamedXContentObject, NamedWriteable, Accountable {

    class PreProcessorParseContext {
        public static final PreProcessorParseContext DEFAULT = new PreProcessorParseContext(false);
        final boolean defaultIsCustomValue;

        public PreProcessorParseContext(boolean defaultIsCustomValue) {
            this.defaultIsCustomValue = defaultIsCustomValue;
        }

        public boolean isCustomByDefault() {
            return defaultIsCustomValue;
        }
    }

    /**
     * The expected input fields
     */
    List<String> inputFields();

    /**
     * @return The resulting output fields. It is imperative that the order is consistent between calls.
     */
    List<String> outputFields();

    /**
     * Process the given fields and their values and return the modified map.
     *
     * NOTE: The passed map object is mutated directly
     * @param fields The fields and their values to process
     */
    void process(Map<String, Object> fields);

    /**
     * @return Reverse lookup map to match resulting features to their original feature name
     */
    Map<String, String> reverseLookup();

    /**
     * @return Is the pre-processor a custom one provided by the user, or automatically created?
     *         This changes how feature importance is calculated, as fields generated by custom processors get individual feature
     *         importance calculations.
     */
    boolean isCustom();

    String getOutputFieldType(String outputField);

}
