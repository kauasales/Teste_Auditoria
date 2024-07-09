/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.expression.function.aggregate;

import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.compute.aggregation.AggregatorFunctionSupplier;
import org.elasticsearch.compute.aggregation.MaxDoubleAggregatorFunctionSupplier;
import org.elasticsearch.compute.aggregation.MaxIntAggregatorFunctionSupplier;
import org.elasticsearch.compute.aggregation.MaxLongAggregatorFunctionSupplier;
import org.elasticsearch.xpack.esql.core.expression.Expression;
import org.elasticsearch.xpack.esql.core.expression.FieldAttribute;
import org.elasticsearch.xpack.esql.core.tree.NodeInfo;
import org.elasticsearch.xpack.esql.core.tree.Source;
import org.elasticsearch.xpack.esql.core.type.DataType;
import org.elasticsearch.xpack.esql.expression.SurrogateExpression;
import org.elasticsearch.xpack.esql.expression.function.FunctionInfo;
import org.elasticsearch.xpack.esql.expression.function.Param;
import org.elasticsearch.xpack.esql.expression.function.scalar.multivalue.MvMax;

import java.io.IOException;
import java.util.List;

public class Max extends NumericAggregate implements SurrogateExpression {
    public static final NamedWriteableRegistry.Entry ENTRY = new NamedWriteableRegistry.Entry(Expression.class, "Max", Max::new);

    @FunctionInfo(
        returnType = { "double", "integer", "long", "date" },
        description = "The maximum value of a numeric field.",
        isAggregation = true
    )
    public Max(Source source, @Param(name = "number", type = { "double", "integer", "long", "date" }) Expression field) {
        super(source, field);
    }

    private Max(StreamInput in) throws IOException {
        super(in);
    }

    @Override
    public String getWriteableName() {
        return ENTRY.name;
    }

    @Override
    protected NodeInfo<Max> info() {
        return NodeInfo.create(this, Max::new, field());
    }

    @Override
    public Max replaceChildren(List<Expression> newChildren) {
        return new Max(source(), newChildren.get(0));
    }

    @Override
    protected boolean supportsDates() {
        return true;
    }

    @Override
    public DataType dataType() {
        return field().dataType();
    }

    @Override
    protected AggregatorFunctionSupplier longSupplier(List<Integer> inputChannels) {
        return new MaxLongAggregatorFunctionSupplier(inputChannels);
    }

    @Override
    protected AggregatorFunctionSupplier intSupplier(List<Integer> inputChannels) {
        return new MaxIntAggregatorFunctionSupplier(inputChannels);
    }

    @Override
    protected AggregatorFunctionSupplier doubleSupplier(List<Integer> inputChannels) {
        return new MaxDoubleAggregatorFunctionSupplier(inputChannels);
    }

    @Override
    public Expression surrogate() {
        if (field().foldable()) {
            return new MvMax(source(), field());
        } else if (field() instanceof FieldAttribute fieldAttribute && fieldAttribute.dataType() == DataType.AGGREGATE_DOUBLE_METRIC) {
            return new Max(source(), fieldAttribute.getAggregateDoubleMetricSubFields().get("max"));
        } else {
            return null;
        }
    }
}
