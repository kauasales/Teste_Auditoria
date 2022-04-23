/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.slm.history;

import org.elasticsearch.client.internal.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xcontent.NamedXContentRegistry;
import org.elasticsearch.xpack.core.ilm.LifecyclePolicy;
import org.elasticsearch.xpack.core.template.IndexTemplateRegistry;
import org.elasticsearch.xpack.core.template.LifecyclePolicyConfig;
import org.elasticsearch.xpack.ilm.IndexLifecycle;

import java.util.Collections;
import java.util.List;

import static org.elasticsearch.xpack.core.ClientHelper.INDEX_LIFECYCLE_ORIGIN;
import static org.elasticsearch.xpack.core.ilm.LifecycleSettings.SLM_HISTORY_INDEX_ENABLED_SETTING;

/**
 * Manages the index template and associated ILM policy for the Snapshot
 * Lifecycle Management history index.
 */
public class SnapshotLifecycleTemplateRegistry extends IndexTemplateRegistry {
    // history (please add a comment why you increased the version here)
    // version 1: initial
    // version 2: converted to hidden index
    // version 3: templates moved to composable templates
    // version 4:converted data stream
    // version 5: add `allow_auto_create` setting
    public static final int INDEX_TEMPLATE_VERSION = 5;

    public static final String SLM_POLICY_NAME = "slm-history-ilm-policy";

    @Override
    protected boolean requiresMasterNode() {
        return true;
    }

    private final boolean slmHistoryEnabled;

    public SnapshotLifecycleTemplateRegistry(
        Settings nodeSettings,
        ClusterService clusterService,
        ThreadPool threadPool,
        Client client,
        NamedXContentRegistry xContentRegistry
    ) {
        super(nodeSettings, clusterService, threadPool, client, xContentRegistry);
        slmHistoryEnabled = SLM_HISTORY_INDEX_ENABLED_SETTING.get(nodeSettings);
    }

    static final List<LifecyclePolicy> LIFECYCLE_POLICIES = List.of(
        new LifecyclePolicyConfig(SLM_POLICY_NAME, "/slm-history-ilm-policy.json").load(
            new NamedXContentRegistry(IndexLifecycle.NAMED_X_CONTENT_ENTRIES)
        )
    );

    @Override
    protected List<LifecyclePolicy> getPolicyConfigs() {
        if (slmHistoryEnabled == false) {
            return Collections.emptyList();
        }
        return LIFECYCLE_POLICIES;
    }

    @Override
    protected String getOrigin() {
        return INDEX_LIFECYCLE_ORIGIN; // TODO use separate SLM origin?
    }
}
