/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.tracing.apm;

import org.apache.lucene.analysis.TokenStream;
import org.elasticsearch.plugin.analysis.api.TokenFilterFactory;
import org.elasticsearch.plugin.api.NamedComponent;

@NamedComponent(name = "yy")// TODO to be removed. test class to see this being picked up by server on startup.
public class YY implements TokenFilterFactory {
    @Override
    public String name() {
        return null;
    }

    @Override
    public TokenStream create(TokenStream tokenStream) {
        return null;
    }
}
