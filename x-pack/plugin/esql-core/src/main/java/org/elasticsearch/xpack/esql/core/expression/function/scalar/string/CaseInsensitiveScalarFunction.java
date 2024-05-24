/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.core.expression.function.scalar.string;

import org.elasticsearch.xpack.esql.core.expression.Expression;
import org.elasticsearch.xpack.esql.core.expression.function.scalar.ScalarFunction;
import org.elasticsearch.xpack.esql.core.tree.Source;

import java.util.List;
import java.util.Objects;

public abstract class CaseInsensitiveScalarFunction extends ScalarFunction {

    private final boolean caseInsensitive;

    protected CaseInsensitiveScalarFunction(Source source, List<Expression> fields, boolean caseInsensitive) {
        super(source, fields);
        this.caseInsensitive = caseInsensitive;
    }

    public boolean isCaseInsensitive() {
        return caseInsensitive;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), isCaseInsensitive());
    }

    @Override
    public boolean equals(Object other) {
        return super.equals(other) && Objects.equals(((CaseInsensitiveScalarFunction) other).caseInsensitive, caseInsensitive);
    }
}
