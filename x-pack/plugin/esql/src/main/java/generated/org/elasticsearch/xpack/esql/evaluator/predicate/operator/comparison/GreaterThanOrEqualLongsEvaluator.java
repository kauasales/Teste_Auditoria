// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License
// 2.0; you may not use this file except in compliance with the Elastic License
// 2.0.
package org.elasticsearch.xpack.esql.evaluator.predicate.operator.comparison;

import java.lang.Override;
import java.lang.String;
import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.BooleanBlock;
import org.elasticsearch.compute.data.BooleanVector;
import org.elasticsearch.compute.data.LongBlock;
import org.elasticsearch.compute.data.LongVector;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.operator.DriverContext;
import org.elasticsearch.compute.operator.EvalOperator;
import org.elasticsearch.core.Releasables;

/**
 * {@link EvalOperator.ExpressionEvaluator} implementation for {@link GreaterThanOrEqual}.
 * This class is generated. Do not edit it.
 */
public final class GreaterThanOrEqualLongsEvaluator implements EvalOperator.ExpressionEvaluator {
  private final EvalOperator.ExpressionEvaluator lhs;

  private final EvalOperator.ExpressionEvaluator rhs;

  private final DriverContext driverContext;

  public GreaterThanOrEqualLongsEvaluator(EvalOperator.ExpressionEvaluator lhs,
      EvalOperator.ExpressionEvaluator rhs, DriverContext driverContext) {
    this.lhs = lhs;
    this.rhs = rhs;
    this.driverContext = driverContext;
  }

  @Override
  public Block eval(Page page) {
    Block lhsUncastBlock = lhs.eval(page);
    if (lhsUncastBlock.areAllValuesNull()) {
      return Block.constantNullBlock(page.getPositionCount());
    }
    LongBlock lhsBlock = (LongBlock) lhsUncastBlock;
    Block rhsUncastBlock = rhs.eval(page);
    if (rhsUncastBlock.areAllValuesNull()) {
      return Block.constantNullBlock(page.getPositionCount());
    }
    LongBlock rhsBlock = (LongBlock) rhsUncastBlock;
    LongVector lhsVector = lhsBlock.asVector();
    if (lhsVector == null) {
      return eval(page.getPositionCount(), lhsBlock, rhsBlock);
    }
    LongVector rhsVector = rhsBlock.asVector();
    if (rhsVector == null) {
      return eval(page.getPositionCount(), lhsBlock, rhsBlock);
    }
    return eval(page.getPositionCount(), lhsVector, rhsVector).asBlock();
  }

  public BooleanBlock eval(int positionCount, LongBlock lhsBlock, LongBlock rhsBlock) {
    BooleanBlock.Builder result = BooleanBlock.newBlockBuilder(positionCount);
    position: for (int p = 0; p < positionCount; p++) {
      if (lhsBlock.isNull(p) || lhsBlock.getValueCount(p) != 1) {
        result.appendNull();
        continue position;
      }
      if (rhsBlock.isNull(p) || rhsBlock.getValueCount(p) != 1) {
        result.appendNull();
        continue position;
      }
      result.appendBoolean(GreaterThanOrEqual.processLongs(lhsBlock.getLong(lhsBlock.getFirstValueIndex(p)), rhsBlock.getLong(rhsBlock.getFirstValueIndex(p))));
    }
    return result.build();
  }

  public BooleanVector eval(int positionCount, LongVector lhsVector, LongVector rhsVector) {
    BooleanVector.Builder result = BooleanVector.newVectorBuilder(positionCount);
    position: for (int p = 0; p < positionCount; p++) {
      result.appendBoolean(GreaterThanOrEqual.processLongs(lhsVector.getLong(p), rhsVector.getLong(p)));
    }
    return result.build();
  }

  @Override
  public String toString() {
    return "GreaterThanOrEqualLongsEvaluator[" + "lhs=" + lhs + ", rhs=" + rhs + "]";
  }

  @Override
  public void close() {
    Releasables.closeExpectNoException(lhs, rhs);
  }
}
