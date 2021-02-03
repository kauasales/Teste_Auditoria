/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.runtimefields.query;

import org.apache.lucene.index.Term;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.QueryVisitor;
import org.apache.lucene.util.automaton.ByteRunAutomaton;
import org.elasticsearch.script.Script;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import static java.util.stream.Collectors.toCollection;
import static org.hamcrest.Matchers.equalTo;

public class StringScriptFieldTermsQueryTests extends AbstractStringScriptFieldQueryTestCase<StringScriptFieldTermsQuery> {
    @Override
    protected StringScriptFieldTermsQuery createTestInstance() {
        Set<String> terms = new TreeSet<>(Arrays.asList(generateRandomStringArray(4, 6, false, false)));
        return new StringScriptFieldTermsQuery(randomScript(), leafFactory, randomAlphaOfLength(5), terms);
    }

    @Override
    protected StringScriptFieldTermsQuery copy(StringScriptFieldTermsQuery orig) {
        return new StringScriptFieldTermsQuery(orig.script(), leafFactory, orig.fieldName(), orig.terms());
    }

    @Override
    protected StringScriptFieldTermsQuery mutate(StringScriptFieldTermsQuery orig) {
        Script script = orig.script();
        String fieldName = orig.fieldName();
        Set<String> terms = orig.terms();
        switch (randomInt(2)) {
            case 0:
                script = randomValueOtherThan(script, this::randomScript);
                break;
            case 1:
                fieldName += "modified";
                break;
            case 2:
                terms = new TreeSet<>(orig.terms());
                terms.add(randomAlphaOfLength(7));
                break;
            default:
                fail();
        }
        return new StringScriptFieldTermsQuery(script, leafFactory, fieldName, terms);
    }

    @Override
    public void testMatches() {
        StringScriptFieldTermsQuery query = new StringScriptFieldTermsQuery(
            randomScript(),
            leafFactory,
            "test",
            org.elasticsearch.common.collect.Set.of("foo", "bar")
        );
        assertTrue(query.matches(org.elasticsearch.common.collect.List.of("foo")));
        assertTrue(query.matches(org.elasticsearch.common.collect.List.of("bar")));
        assertFalse(query.matches(org.elasticsearch.common.collect.List.of("baz")));
        assertTrue(query.matches(org.elasticsearch.common.collect.List.of("foo", "baz")));
        assertTrue(query.matches(org.elasticsearch.common.collect.List.of("bar", "baz")));
        assertFalse(query.matches(org.elasticsearch.common.collect.List.of("baz", "bort")));
    }

    @Override
    protected void assertToString(StringScriptFieldTermsQuery query) {
        assertThat(query.toString(query.fieldName()), equalTo(query.terms().toString()));
    }

    @Override
    public void testVisit() {
        StringScriptFieldTermsQuery query = createTestInstance();
        Set<Term> allTerms = new TreeSet<>();
        query.visit(new QueryVisitor() {
            @Override
            public void consumeTerms(Query query, Term... terms) {
                allTerms.addAll(Arrays.asList(terms));
            }

            @Override
            public void consumeTermsMatching(Query query, String field, Supplier<ByteRunAutomaton> automaton) {
                fail();
            }
        });
        assertThat(allTerms, equalTo(query.terms().stream().map(t -> new Term(query.fieldName(), t)).collect(toCollection(TreeSet::new))));
    }
}
