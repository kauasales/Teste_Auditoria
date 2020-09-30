/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.dataframe.evaluation.classification;

import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.test.AbstractWireSerializingTestCase;
import org.elasticsearch.xpack.core.ml.dataframe.evaluation.MlEvaluationNamedXContentProvider;
import org.elasticsearch.xpack.core.ml.dataframe.evaluation.classification.AbstractAucRoc.AucRocPoint;
import org.elasticsearch.xpack.core.ml.dataframe.evaluation.classification.AbstractAucRoc.Result;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AucRocResultTests extends AbstractWireSerializingTestCase<Result> {

    public static Result createRandom() {
        double score = randomDoubleBetween(0.0, 1.0, true);
        Long docCount = randomBoolean() ? randomLong() : null;
        List<AucRocPoint> curve =
            Stream
                .generate(() -> new AucRocPoint(randomDouble(), randomDouble(), randomDouble()))
                .limit(randomIntBetween(0, 20))
                .collect(Collectors.toList());
        return new Result(score, docCount, curve);
    }

    @Override
    protected NamedWriteableRegistry getNamedWriteableRegistry() {
        return new NamedWriteableRegistry(MlEvaluationNamedXContentProvider.getNamedWriteables());
    }

    @Override
    protected Result createTestInstance() {
        return createRandom();
    }

    @Override
    protected Writeable.Reader<Result> instanceReader() {
        return Result::new;
    }
}
