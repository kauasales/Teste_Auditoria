/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz;

import org.elasticsearch.test.ESTestCase;

import java.util.List;
import java.util.function.Predicate;

import static org.hamcrest.Matchers.is;

public class AuthorizationEngineTests extends ESTestCase {

    public void testIndexAuthorizationResultFailureMessage() {
        final Predicate<String> restrictedIndex = s -> s.startsWith(".");
        assertThat(
            AuthorizationEngine.IndexAuthorizationResult.getFailureDescription(List.of("index-1", "index-2", ".index-3"), restrictedIndex),
            is("on indices [index-1,index-2] and restricted indices [.index-3]")
        );

        assertThat(
            AuthorizationEngine.IndexAuthorizationResult.getFailureDescription(List.of("index-1"), restrictedIndex),
            is("on indices [index-1]")
        );

        assertThat(
            AuthorizationEngine.IndexAuthorizationResult.getFailureDescription(
                List.of(".index-1", ".index-2", ".index-3"),
                restrictedIndex
            ),
            is("on restricted indices [.index-1,.index-2,.index-3]")
        );
    }

}
