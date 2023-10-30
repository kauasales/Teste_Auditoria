// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License
// 2.0; you may not use this file except in compliance with the Elastic License
// 2.0.
package org.elasticsearch.xpack.esql.evaluator.predicate.operator.comparison;

import java.lang.Override;
import java.lang.String;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.BooleanBlock;
import org.elasticsearch.compute.data.BooleanVector;
import org.elasticsearch.compute.data.BytesRefBlock;
import org.elasticsearch.compute.data.BytesRefVector;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.operator.DriverContext;
import org.elasticsearch.compute.operator.EvalOperator;
import org.elasticsearch.core.Releasables;

/**
 * {@link EvalOperator.ExpressionEvaluator} implementation for {@link NotEquals}.
 * This class is generated. Do not edit it.
 */
public final class NotEqualsKeywordsEvaluator implements EvalOperator.ExpressionEvaluator {
  private final EvalOperator.ExpressionEvaluator lhs;

  private final EvalOperator.ExpressionEvaluator rhs;

  private final DriverContext driverContext;

  public NotEqualsKeywordsEvaluator(EvalOperator.ExpressionEvaluator lhs,
      EvalOperator.ExpressionEvaluator rhs, DriverContext driverContext) {
    this.lhs = lhs;
    this.rhs = rhs;
    this.driverContext = driverContext;
  }

  @Override
  public Block.Ref eval(Page page) {
    try (Block.Ref lhsRef = lhs.eval(page)) {
      BytesRefBlock lhsBlock = (BytesRefBlock) lhsRef.block();
      try (Block.Ref rhsRef = rhs.eval(page)) {
        BytesRefBlock rhsBlock = (BytesRefBlock) rhsRef.block();
        BytesRefVector lhsVector = lhsBlock.asVector();
        if (lhsVector == null) {
          return Block.Ref.floating(eval(page.getPositionCount(), lhsBlock, rhsBlock));
        }
        BytesRefVector rhsVector = rhsBlock.asVector();
        if (rhsVector == null) {
          return Block.Ref.floating(eval(page.getPositionCount(), lhsBlock, rhsBlock));
        }
        return Block.Ref.floating(eval(page.getPositionCount(), lhsVector, rhsVector).asBlock());
      }
    }
  }

  public BooleanBlock eval(int positionCount, BytesRefBlock lhsBlock, BytesRefBlock rhsBlock) {
    try(BooleanBlock.Builder result = BooleanBlock.newBlockBuilder(positionCount, driverContext.blockFactory())) {
      BytesRef lhsScratch = new BytesRef();
      BytesRef rhsScratch = new BytesRef();
      position: for (int p = 0; p < positionCount; p++) {
        if (lhsBlock.isNull(p) || lhsBlock.getValueCount(p) != 1) {
          result.appendNull();
          continue position;
        }
        if (rhsBlock.isNull(p) || rhsBlock.getValueCount(p) != 1) {
          result.appendNull();
          continue position;
        }
        result.appendBoolean(NotEquals.processKeywords(lhsBlock.getBytesRef(lhsBlock.getFirstValueIndex(p), lhsScratch), rhsBlock.getBytesRef(rhsBlock.getFirstValueIndex(p), rhsScratch)));
      }
      return result.build();
    }
  }

  public BooleanVector eval(int positionCount, BytesRefVector lhsVector, BytesRefVector rhsVector) {
    try(BooleanVector.Builder result = BooleanVector.newVectorBuilder(positionCount, driverContext.blockFactory())) {
      BytesRef lhsScratch = new BytesRef();
      BytesRef rhsScratch = new BytesRef();
      position: for (int p = 0; p < positionCount; p++) {
        result.appendBoolean(NotEquals.processKeywords(lhsVector.getBytesRef(p, lhsScratch), rhsVector.getBytesRef(p, rhsScratch)));
      }
      return result.build();
    }
  }

  @Override
  public String toString() {
    return "NotEqualsKeywordsEvaluator[" + "lhs=" + lhs + ", rhs=" + rhs + "]";
  }

  @Override
  public void close() {
    Releasables.closeExpectNoException(lhs, rhs);
  }

  static class Factory implements EvalOperator.ExpressionEvaluator.Factory {
    private final EvalOperator.ExpressionEvaluator.Factory lhs;

    private final EvalOperator.ExpressionEvaluator.Factory rhs;

    public Factory(EvalOperator.ExpressionEvaluator.Factory lhs,
        EvalOperator.ExpressionEvaluator.Factory rhs) {
      this.lhs = lhs;
      this.rhs = rhs;
    }

    @Override
    public NotEqualsKeywordsEvaluator get(DriverContext context) {
      return new NotEqualsKeywordsEvaluator(lhs.get(context), rhs.get(context), context);
    }

    @Override
    public String toString() {
      return "NotEqualsKeywordsEvaluator[" + "lhs=" + lhs + ", rhs=" + rhs + "]";
    }
  }
}
