/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.index.shard;

import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.logging.PrefixLogger;

public abstract class AbstractIndexShardComponent implements IndexShardComponent {

    protected final Logger logger;
    protected final ShardId shardId;
    protected final IndexSettings indexSettings;

    protected AbstractIndexShardComponent(ShardId shardId, IndexSettings indexSettings) {
        this.shardId = shardId;
        this.indexSettings = indexSettings;
        this.logger = PrefixLogger.getLogger(getClass(), shardId.getId());
    }

    @Override
    public ShardId shardId() {
        return this.shardId;
    }

    @Override
    public IndexSettings indexSettings() {
        return indexSettings;
    }
}
