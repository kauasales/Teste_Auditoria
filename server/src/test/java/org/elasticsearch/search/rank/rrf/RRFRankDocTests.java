/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.search.rank.rrf;

import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.test.AbstractNamedWriteableTestCase;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.search.rank.rrf.RRFRankDoc.NO_RANK;

public class RRFRankDocTests extends AbstractNamedWriteableTestCase<RRFRankDoc> {

    public static RRFRankDoc createTestRRFRankDoc(int queryCount) {
        RRFRankDoc instance = new RRFRankDoc(randomNonNegativeInt(), randomBoolean() ? -1 : randomNonNegativeInt(), queryCount);
        instance.score = randomFloat();
        instance.rank = randomBoolean() ? NO_RANK : randomIntBetween(1, 10000);
        for (int qi = 0; qi < queryCount; ++qi) {
            if (randomBoolean()) {
                instance.positions[qi] = randomIntBetween(1, 10000);
                instance.scores[qi] = randomFloat();
            }
        }
        return instance;
    }

    public static RRFRankDoc createTestRRFRankDoc() {
        int queryCount = randomIntBetween(2, 20);
        return createTestRRFRankDoc(queryCount);
    }

    @Override
    protected RRFRankDoc createTestInstance() {
        return createTestRRFRankDoc();
    }

    @Override
    protected RRFRankDoc mutateInstance(RRFRankDoc instance) throws IOException {
        RRFRankDoc mutated = new RRFRankDoc(instance.doc, instance.shardIndex, instance.positions.length);
        mutated.score = instance.score;
        mutated.rank = instance.rank;
        System.arraycopy(instance.positions, 0, mutated.positions, 0, instance.positions.length);
        System.arraycopy(instance.scores, 0, mutated.scores, 0, instance.positions.length);
        mutated.rank = mutated.rank == NO_RANK ? randomIntBetween(1, 10000) : NO_RANK;
        if (rarely()) {
            int ri = randomInt(mutated.positions.length - 1);
            mutated.positions[ri] = mutated.positions[ri] == NO_RANK ? randomIntBetween(1, 10000) : NO_RANK;
        }
        if (rarely()) {
            int ri = randomInt(mutated.positions.length - 1);
            mutated.scores[ri] = randomFloat();
        }
        if (rarely()) {
            mutated.doc = randomNonNegativeInt();
        }
        if (rarely()) {
            mutated.score = randomFloat();
        }
        if (frequently()) {
            mutated.shardIndex = mutated.shardIndex == -1 ? randomNonNegativeInt() : -1;
        }
        return mutated;
    }

    @Override
    protected NamedWriteableRegistry getNamedWriteableRegistry() {
        return new NamedWriteableRegistry(List.of(new NamedWriteableRegistry.Entry(RRFRankDoc.class, "rrf", RRFRankDoc::new)));
    }

    @Override
    protected Class<RRFRankDoc> categoryClass() {
        return RRFRankDoc.class;
    }
}
