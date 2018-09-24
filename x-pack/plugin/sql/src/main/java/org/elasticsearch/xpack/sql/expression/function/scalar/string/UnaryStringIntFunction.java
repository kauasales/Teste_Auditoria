/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.sql.expression.function.scalar.string;

import org.elasticsearch.xpack.sql.expression.Expression;
import org.elasticsearch.xpack.sql.expression.Expressions;
import org.elasticsearch.xpack.sql.expression.FieldAttribute;
import org.elasticsearch.xpack.sql.expression.function.scalar.UnaryScalarFunction;
import org.elasticsearch.xpack.sql.expression.function.scalar.string.StringProcessor.StringOperation;
import org.elasticsearch.xpack.sql.expression.gen.pipeline.Pipe;
import org.elasticsearch.xpack.sql.expression.gen.pipeline.UnaryPipe;
import org.elasticsearch.xpack.sql.expression.gen.script.ScriptTemplate;
import org.elasticsearch.xpack.sql.tree.Location;

import java.util.Locale;
import java.util.Objects;

import static java.lang.String.format;
import static org.elasticsearch.xpack.sql.expression.gen.script.ParamsBuilder.paramsBuilder;

/**
 * Base unary function for text manipulating SQL functions that receive as parameter a number
 */
public abstract class UnaryStringIntFunction extends UnaryScalarFunction {

    protected UnaryStringIntFunction(Location location, Expression field) {
        super(location, field);
    }

    @Override
    public boolean foldable() {
        return field().foldable();
    }

    @Override
    public Object fold() {
        return operation().apply(field().fold());
    }

    @Override
    protected TypeResolution resolveType() {
        if (!childrenResolved()) {
            return new TypeResolution("Unresolved children");
        }

        return field().dataType().isInteger ? TypeResolution.TYPE_RESOLVED : new TypeResolution(
                "'%s' requires a integer type, received %s", operation(), field().dataType().esType);
    }

    @Override
    protected final Pipe makePipe() {
        return new UnaryPipe(location(), this, Expressions.pipe(field()), new StringProcessor(operation()));
    }

    protected abstract StringOperation operation();
    
    @Override
    public ScriptTemplate scriptWithField(FieldAttribute field) {
        return new ScriptTemplate(formatScript("doc[{}].value"),
                paramsBuilder().variable(field.name()).build(),
                dataType());
    }
    
    @Override
    public String formatScript(String template) {
        return super.formatScript(
                format(Locale.ROOT, "{sql}.%s(%s)",
                        operation().toString().toLowerCase(Locale.ROOT),
                        template));
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || obj.getClass() != getClass()) {
            return false;
        }
        UnaryStringIntFunction other = (UnaryStringIntFunction) obj;
        return Objects.equals(other.field(), field());
    }

    @Override
    public int hashCode() {
        return Objects.hash(field());
    }
}