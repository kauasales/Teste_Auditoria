/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.search.action;

import org.elasticsearch.action.ActionType;

public class ClosePointInTimeAction extends ActionType<ClosePointInTimeResponse> {

    public static final ClosePointInTimeAction INSTANCE = new ClosePointInTimeAction();
    public static final String NAME = "indices:data/read/close_point_in_time";

    private ClosePointInTimeAction() {
        super(NAME, ClosePointInTimeResponse::new);
    }
}
