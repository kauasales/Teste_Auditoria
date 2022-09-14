/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.reservedstate.ReservedClusterStateHandler;
import org.elasticsearch.reservedstate.ReservedClusterStateHandlerProvider;

import java.util.Collection;
import java.util.Collections;

/**
 * Mock Security Provider implementation for the {@link ReservedClusterStateHandlerProvider} service interface. This is used
 * for {@link org.elasticsearch.test.ESIntegTestCase} because the Security Plugin is really LocalStateSecurity in those tests.
 */
public class LocalReservedSecurityStateHandlerProvider implements ReservedClusterStateHandlerProvider {
    private final LocalStateSecurity plugin;

    public LocalReservedSecurityStateHandlerProvider() {
        throw new IllegalStateException("Provider must be constructed using PluginsService");
    }

    public LocalReservedSecurityStateHandlerProvider(LocalStateSecurity plugin) {
        this.plugin = plugin;
    }

    @Override
    public Collection<ReservedClusterStateHandler<?>> handlers() {
        for (Plugin subPlugin : plugin.plugins()) {
            if (subPlugin instanceof Security security) {
                return security.reservedClusterStateHandlers();
            }
        }
        return Collections.emptyList();
    }
}
