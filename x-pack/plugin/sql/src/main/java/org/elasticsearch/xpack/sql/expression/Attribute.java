/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.sql.expression;

import org.elasticsearch.xpack.sql.SqlIllegalArgumentException;
import org.elasticsearch.xpack.sql.expression.gen.script.ScriptTemplate;
import org.elasticsearch.xpack.sql.tree.Location;
import org.elasticsearch.xpack.sql.tree.NodeInfo;

import java.util.List;
import java.util.Objects;

import static java.util.Collections.emptyList;

/**
 * {@link Expression}s that can be materialized and represent the result columns sent to the client.
 * Typically are converted into constants, functions or Elasticsearch order-bys,
 * aggregations, or queries. They can also be extracted from the result of a search.
 *
 * In the statement {@code SELECT ABS(foo), A, B+C FROM ...} the three named
 * expressions {@code ABS(foo), A, B+C} get converted to attributes and the user can
 * only see Attributes.
 *
 * In the statement {@code SELECT foo FROM TABLE WHERE foo > 10 + 1} both {@code foo} and
 * {@code 10 + 1} are named expressions, the first due to the SELECT, the second due to being a function.
 * However since {@code 10 + 1} is used for filtering it doesn't appear appear in the result set
 * (derived table) and as such it is never translated to an attribute.
 * "foo" on the other hand is since it's a column in the result set.
 *
 * Another example {@code SELECT foo FROM ... WHERE bar > 10 +1} {@code foo} gets
 * converted into an Attribute, bar does not. That's because {@code bar} is used for
 * filtering alone but it's not part of the projection meaning the user doesn't
 * need it in the derived table.
 */
public abstract class Attribute extends NamedExpression {

    // empty - such as a top level attribute in SELECT cause
    // present - table name or a table name alias
    private final String qualifier;

    // can the attr be null - typically used in JOINs
    private final Nullable nullable;

    public Attribute(Location location, String name, String qualifier, ExpressionId id) {
        this(location, name, qualifier, Nullable.POSSIBLY, id);
    }

    public Attribute(Location location, String name, String qualifier, Nullable nullable, ExpressionId id) {
        this(location, name, qualifier, nullable, id, false);
    }

    public Attribute(Location location, String name, String qualifier, Nullable nullable, ExpressionId id, boolean synthetic) {
        super(location, name, emptyList(), id, synthetic);
        this.qualifier = qualifier;
        this.nullable = nullable;
    }

    @Override
    public final Expression replaceChildren(List<Expression> newChildren) {
        throw new UnsupportedOperationException("this type of node doesn't have any children to replace");
    }

    @Override
    public ScriptTemplate asScript() {
        throw new SqlIllegalArgumentException("Encountered a bug - an attribute should never be scripted");
    }

    public String qualifier() {
        return qualifier;
    }

    public String qualifiedName() {
        return qualifier == null ? name() : qualifier + "." + name();
    }

    @Override
    public Nullable nullable() {
        return nullable;
    }

    @Override
    public AttributeSet references() {
        return new AttributeSet(this);
    }

    public Attribute withLocation(Location location) {
        return Objects.equals(location(), location) ? this : clone(location, name(), qualifier(), nullable(), id(), synthetic());
    }

    public Attribute withQualifier(String qualifier) {
        return Objects.equals(qualifier(), qualifier) ? this : clone(location(), name(), qualifier, nullable(), id(), synthetic());
    }

    public Attribute withNullability(Nullable nullable) {
        return Objects.equals(nullable(), nullable) ? this : clone(location(), name(), qualifier(), nullable, id(), synthetic());
    }

    protected abstract Attribute clone(Location location, String name, String qualifier, Nullable nullable, ExpressionId id,
                                       boolean synthetic);

    @Override
    public Attribute toAttribute() {
        return this;
    }

    @Override
    public int semanticHash() {
        return id().hashCode();
    }

    @Override
    protected NodeInfo<? extends Expression> info() {
        return null;
    }

    @Override
    public boolean semanticEquals(Expression other) {
        return other instanceof Attribute ? id().equals(((Attribute) other).id()) : false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), qualifier, nullable);
    }

    @Override
    public boolean equals(Object obj) {
        if (super.equals(obj)) {
            Attribute other = (Attribute) obj;
            return Objects.equals(qualifier, other.qualifier)
                    && Objects.equals(nullable, other.nullable);
        }

        return false;
    }

    @Override
    public String toString() {
        return name() + "{" + label() + "}" + "#" + id();
    }

    protected abstract String label();
}
