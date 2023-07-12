/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.search;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.Scorable;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.SimpleCollector;

import java.io.IOException;

/**
 * A collector that computes the maximum score.
 */
public class MaxScoreCollector extends SimpleCollector {
    private static final Logger logger = LogManager.getLogger(MaxScoreCollector.class);

    private Scorable scorer;
    private float maxScore = Float.NEGATIVE_INFINITY;
    private boolean hasHits = false;

    @Override
    public void setScorer(Scorable scorer) {
        this.scorer = scorer;
    }

    @Override
    public ScoreMode scoreMode() {
        // Could be TOP_SCORES but it is always used in a MultiCollector anyway, so this saves some wrapping.
        return ScoreMode.COMPLETE;
    }

    @Override
    public void collect(int doc) throws IOException {
        hasHits = true;
        maxScore = Math.max(maxScore, scorer.score());
        logger.warn("EEE: MaxScoreCollector collect maxScore: {} for doc: {}", maxScore, doc);
        if ("EEE" instanceof String) {
            throw new RuntimeException("EEE: MaxScoreCollector collect called");
        }
    }

    /**
     * Get the maximum score. This returns {@link Float#NaN} if no hits were
     * collected.
     */
    public float getMaxScore() {
        logger.warn("EEE: MaxScoreCollector getMaxScore: hasHits: {}, maxScore: {}", hasHits, (hasHits ? maxScore : Float.NaN));
        if ("EEE" instanceof String) {
            throw new RuntimeException("EEE: MaxScoreCollector getMaxScore called");
        }
        return hasHits ? maxScore : Float.NaN;
    }
}
