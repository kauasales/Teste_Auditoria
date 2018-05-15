/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.indexlifecycle;

import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.test.AbstractXContentTestCase;
import org.elasticsearch.test.EqualsHashCodeTestUtils;
import org.elasticsearch.xpack.core.indexlifecycle.AllocationRoutedStep.Info;

import java.io.IOException;

public class AllocationRoutedStepInfoTests extends AbstractXContentTestCase<AllocationRoutedStep.Info> {

    @Override
    protected Info createTestInstance() {
        return new Info(randomNonNegativeLong(), randomBoolean());
    }

    @Override
    protected Info doParseInstance(XContentParser parser) throws IOException {
        return Info.PARSER.apply(parser, null);
    }

    @Override
    protected boolean supportsUnknownFields() {
        return false;
    }

    public final void testEqualsAndHashcode() {
        for (int runs = 0; runs < NUMBER_OF_TEST_RUNS; runs++) {
            EqualsHashCodeTestUtils.checkEqualsAndHashCode(createTestInstance(), this::copyInstance, this::mutateInstance);
        }
    }

    protected final Info copyInstance(Info instance) throws IOException {
        return new Info(instance.getNumberShardsLeftToAllocate(), instance.allShardsActive());
    }

    protected Info mutateInstance(Info instance) throws IOException {
        long shardsToAllocate = instance.getNumberShardsLeftToAllocate();
        boolean allShardsActive = instance.allShardsActive();
        switch (between(0, 1)) {
        case 0:
            shardsToAllocate += between(1, 20);
            break;
        case 1:
            allShardsActive = allShardsActive == false;
            break;
        default:
            throw new AssertionError("Illegal randomisation branch");
        }
        return new Info(shardsToAllocate, allShardsActive);
    }

}
