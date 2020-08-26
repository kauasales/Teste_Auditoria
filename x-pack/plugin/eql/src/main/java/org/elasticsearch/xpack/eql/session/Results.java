/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.eql.session;

import org.apache.lucene.search.TotalHits;
import org.apache.lucene.search.TotalHits.Relation;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.xpack.eql.action.EqlSearchResponse.Count;
import org.elasticsearch.xpack.eql.action.EqlSearchResponse.Event;
import org.elasticsearch.xpack.eql.action.EqlSearchResponse.Sequence;
import org.elasticsearch.xpack.eql.session.Payload.Type;

import java.util.List;

public class Results {

    private final TotalHits totalHits;
    private final List<?> results;
    private final boolean timedOut;
    private final TimeValue tookTime;
    private final Type type;

    public static Results fromPayload(Payload payload) {
        List<?> values = payload.values();
        return new Results(new TotalHits(values.size(), Relation.EQUAL_TO), payload.timeTook(), false, values, payload.resultType());
    }
    
    Results(TotalHits totalHits, TimeValue tookTime, boolean timedOut, List<?> results, Type type) {
        this.totalHits = totalHits;
        this.tookTime = tookTime;
        this.timedOut = timedOut;
        this.results = results;
        this.type = type;
    }

    public TotalHits totalHits() {
        return totalHits;
    }

    @SuppressWarnings("unchecked")
    public List<Event> events() {
        return type == Type.EVENT ? (List<Event>) results : null;
    }

    @SuppressWarnings("unchecked")
    public List<Sequence> sequences() {
        return type == Type.SEQUENCE ? (List<Sequence>) results : null;
    }

    @SuppressWarnings("unchecked")
    public List<Count> counts() {
        return type == Type.COUNT ? (List<Count>) results : null;
    }

    public TimeValue tookTime() {
        return tookTime;
    }

    public boolean timedOut() {
        return timedOut;
    }
}