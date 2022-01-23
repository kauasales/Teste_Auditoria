/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.discovery;

import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.core.Releasable;

/**
 * The result of a "probe" connection to a transport address, if it successfully discovered a valid node and established a full connection
 * with it.
 */
public record ProbeConnectionResult(DiscoveryNode discoveryNode, Releasable releasable) implements Releasable {

    @Override
    public void close() {
        releasable.close();
    }
}
