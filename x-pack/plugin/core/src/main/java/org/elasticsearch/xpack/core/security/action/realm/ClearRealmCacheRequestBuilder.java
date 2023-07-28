/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security.action.realm;

import org.elasticsearch.action.support.nodes.NodesOperationRequestBuilder;
import org.elasticsearch.client.internal.ElasticsearchClient;

public class ClearRealmCacheRequestBuilder extends NodesOperationRequestBuilder<
    ClearRealmCacheRequest,
    ClearRealmCacheResponse,
    ClearRealmCacheRequestBuilder> {

    public ClearRealmCacheRequestBuilder(ElasticsearchClient client) {
        super(client, ClearRealmCacheAction.INSTANCE, new ClearRealmCacheRequest());
    }

}
