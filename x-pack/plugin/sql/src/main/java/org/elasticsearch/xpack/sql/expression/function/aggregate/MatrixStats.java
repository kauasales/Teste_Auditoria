/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.sql.expression.function.aggregate;

import org.elasticsearch.xpack.ql.expression.Expression;
import org.elasticsearch.xpack.ql.tree.NodeInfo;
import org.elasticsearch.xpack.ql.tree.Source;

import java.util.List;

public class MatrixStats extends CompoundNumericAggregate {

    public MatrixStats(Source source, Expression field) {
        super(source, field);
    }

    @Override
    protected NodeInfo<MatrixStats> info() {
        return NodeInfo.create(this, MatrixStats::new, field());
    }

    @Override
    protected MatrixStats replaceChildren(List<Expression> newChildren) {
        return new MatrixStats(source(), newChildren.get(0));
    }
}
