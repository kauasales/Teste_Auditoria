// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License
// 2.0; you may not use this file except in compliance with the Elastic License
// 2.0.
package org.elasticsearch.xpack.esql.expression.function.scalar.string;

import java.lang.IllegalArgumentException;
import java.lang.Override;
import java.lang.String;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.BytesRefBlock;
import org.elasticsearch.compute.data.BytesRefVector;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.operator.DriverContext;
import org.elasticsearch.compute.operator.EvalOperator;
import org.elasticsearch.core.Releasables;
import org.elasticsearch.xpack.esql.expression.function.Warnings;
import org.elasticsearch.xpack.ql.tree.Source;

/**
 * {@link EvalOperator.ExpressionEvaluator} implementation for {@link LTrim}.
 * This class is generated. Do not edit it.
 */
public final class LTrimEvaluator implements EvalOperator.ExpressionEvaluator {
  private final Warnings warnings;

  private final EvalOperator.ExpressionEvaluator val;

  private final DriverContext driverContext;

  public LTrimEvaluator(Source source, EvalOperator.ExpressionEvaluator val,
      DriverContext driverContext, Warnings warnings) {
    this.val = val;
    this.driverContext = driverContext;
    this.warnings = warnings;
  }

  @Override
  public Block eval(Page page) {
    try (BytesRefBlock valBlock = (BytesRefBlock) val.eval(page)) {
      BytesRefVector valVector = valBlock.asVector();
      if (valVector == null) {
        return eval(page.getPositionCount(), valBlock);
      }
      return eval(page.getPositionCount(), valVector).asBlock();
    }
  }

  public BytesRefBlock eval(int positionCount, BytesRefBlock valBlock) {
    try(BytesRefBlock.Builder result = driverContext.blockFactory().newBytesRefBlockBuilder(positionCount)) {
      BytesRef valScratch = new BytesRef();
      position: for (int p = 0; p < positionCount; p++) {
        if (valBlock.isNull(p)) {
          result.appendNull();
          continue position;
        }
        if (valBlock.getValueCount(p) != 1) {
          if (valBlock.getValueCount(p) > 1) {
            warnings.registerException(new IllegalArgumentException("single-value function encountered multi-value"));
          }
          result.appendNull();
          continue position;
        }
        result.appendBytesRef(LTrim.process(valBlock.getBytesRef(valBlock.getFirstValueIndex(p), valScratch)));
      }
      return result.build();
    }
  }

  public BytesRefVector eval(int positionCount, BytesRefVector valVector) {
    try(BytesRefVector.Builder result = driverContext.blockFactory().newBytesRefVectorBuilder(positionCount)) {
      BytesRef valScratch = new BytesRef();
      position: for (int p = 0; p < positionCount; p++) {
        result.appendBytesRef(LTrim.process(valVector.getBytesRef(p, valScratch)));
      }
      return result.build();
    }
  }

  @Override
  public String toString() {
    return "LTrimEvaluator[" + "val=" + val + "]";
  }

  @Override
  public void close() {
    Releasables.closeExpectNoException(val);
  }

  static class Factory implements EvalOperator.ExpressionEvaluator.Factory {
    private final Source source;

    private final EvalOperator.ExpressionEvaluator.Factory val;

    public Factory(Source source, EvalOperator.ExpressionEvaluator.Factory val) {
      this.source = source;
      this.val = val;
    }

    @Override
    public LTrimEvaluator get(DriverContext context, boolean collectWarnings) {
      return new LTrimEvaluator(source, val.get(context, collectWarnings), context, collectWarnings ? new Warnings(source) : Warnings.NOOP_WARNINGS);
    }

    @Override
    public String toString() {
      return "LTrimEvaluator[" + "val=" + val + "]";
    }
  }
}
