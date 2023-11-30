/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.test.rest;

import org.elasticsearch.Version;
import org.elasticsearch.features.FeatureSpecification;
import org.elasticsearch.features.NodeFeature;

import java.util.Map;

import static java.util.Map.entry;

/**
 * This class groups historical features that have been removed from the production codebase, but are still used by the test
 * framework to support BwC tests. Rather than leaving them in the main src we group them here, so it's clear they are not used in
 * production code anymore.
 */
public class RestTestLegacyFeatures implements FeatureSpecification {
    public static final NodeFeature ML_STATE_RESET_FALLBACK_ON_DISABLED = new NodeFeature("ml.state_reset_fallback_on_disabled");
    public static final NodeFeature FEATURE_STATE_RESET_SUPPORTED = new NodeFeature("system_indices.feature_state_reset_supported");
    public static final NodeFeature SYSTEM_INDICES_REST_ACCESS_ENFORCED = new NodeFeature("system_indices.rest_access_enforced");
    public static final NodeFeature HIDDEN_INDICES_SUPPORTED = new NodeFeature("indices.hidden_supported");
    public static final NodeFeature COMPONENT_TEMPLATE_SUPPORTED = new NodeFeature("indices.component_template_supported");
    public static final NodeFeature DELETE_TEMPLATE_MULTIPLE_NAMES_SUPPORTED = new NodeFeature(
        "indices.delete_template_multiple_names_supported"
    );
    public static final NodeFeature ML_NEW_MEMORY_FORMAT = new NodeFeature("ml.new_memory_format");

    /** These are "pure test" features: normally we would not need them, and test for TransportVersion/fallback to Version (see for example
     * {@code ESRestTestCase#minimumTransportVersion()}. However, some tests explicitly check and validate the content of a response, so
     * we need these features to support them.
     */
    public static final NodeFeature TRANSPORT_VERSION_SUPPORTED = new NodeFeature("transport_version_supported");
    public static final NodeFeature STATE_REPLACED_TRANSPORT_VERSION_WITH_NODES_VERSION = new NodeFeature(
        "state.transport_version_to_nodes_version"
    );

    // Ref: https://github.com/elastic/elasticsearch/pull/86416
    public static final NodeFeature ML_MEMORY_OVERHEAD_FIXED = new NodeFeature("ml.memory_overhead_fixed");

    @Override
    public Map<NodeFeature, Version> getHistoricalFeatures() {
        return Map.ofEntries(
            entry(FEATURE_STATE_RESET_SUPPORTED, Version.V_7_13_0),
            entry(SYSTEM_INDICES_REST_ACCESS_ENFORCED, Version.V_8_0_0),
            entry(HIDDEN_INDICES_SUPPORTED, Version.V_7_7_0),
            entry(COMPONENT_TEMPLATE_SUPPORTED, Version.V_7_8_0),
            entry(DELETE_TEMPLATE_MULTIPLE_NAMES_SUPPORTED, Version.V_7_13_0),
            entry(ML_STATE_RESET_FALLBACK_ON_DISABLED, Version.V_8_7_0),
            entry(ML_NEW_MEMORY_FORMAT, Version.V_8_11_0),
            entry(TRANSPORT_VERSION_SUPPORTED, Version.V_8_8_0),
            entry(STATE_REPLACED_TRANSPORT_VERSION_WITH_NODES_VERSION, Version.V_8_11_0),
            entry(ML_MEMORY_OVERHEAD_FIXED, Version.V_8_2_1)
        );
    }
}
