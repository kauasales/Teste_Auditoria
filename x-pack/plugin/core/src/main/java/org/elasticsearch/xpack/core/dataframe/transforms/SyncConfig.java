/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.dataframe.transforms;

import org.elasticsearch.common.io.stream.NamedWriteable;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.index.query.QueryBuilder;

public interface SyncConfig extends ToXContentObject, NamedWriteable {

    /**
     * Validate configuration
     *
     * @return true if valid
     */
    boolean isValid();

    QueryBuilder getBoundaryQuery(DataFrameTransformCheckpoint checkpoint);

    QueryBuilder getChangesQuery(DataFrameTransformCheckpoint oldCheckpoint, DataFrameTransformCheckpoint newCheckpoint);
}
