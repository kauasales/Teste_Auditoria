/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.expression.function.scalar.string;

import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.xpack.esql.core.expression.Expression;
import org.elasticsearch.xpack.esql.core.tree.Source;
import org.elasticsearch.xpack.esql.expression.AbstractVarargsSerializationTests;
import org.elasticsearch.xpack.esql.expression.function.scalar.EsqlScalarFunction;

import java.util.List;

public class ConcatSerializationTests extends AbstractVarargsSerializationTests<Concat> {
    @Override
    protected List<NamedWriteableRegistry.Entry> getNamedWriteables() {
        return EsqlScalarFunction.getNamedWriteables();
    }

    @Override
    protected Concat create(Source source, Expression first, List<Expression> rest) {
        return new Concat(source, first, rest);
    }
}
