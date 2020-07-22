/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.runtimefields;

import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.util.ArrayUtil;
import org.elasticsearch.painless.spi.Whitelist;
import org.elasticsearch.painless.spi.WhitelistLoader;
import org.elasticsearch.script.ScriptContext;
import org.elasticsearch.script.ScriptFactory;
import org.elasticsearch.search.lookup.SearchLookup;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public abstract class DoubleScriptFieldScript extends AbstractNumberScriptFieldScript {
    public static final ScriptContext<Factory> CONTEXT = new ScriptContext<>("double_script_field", Factory.class);

    static List<Whitelist> whitelist() {
        return List.of(WhitelistLoader.loadFromResourceFiles(RuntimeFieldsPainlessExtension.class, "double_whitelist.txt"));
    }

    public static final String[] PARAMETERS = {};

    public interface Factory extends ScriptFactory {
        LeafFactory newFactory(Map<String, Object> params, SearchLookup searchLookup);
    }

    public interface LeafFactory {
        DoubleScriptFieldScript newInstance(LeafReaderContext ctx) throws IOException;
    }

    private double[] values = new double[1];

    public DoubleScriptFieldScript(Map<String, Object> params, SearchLookup searchLookup, LeafReaderContext ctx) {
        super(params, searchLookup, ctx);
    }

    public final double[] values() {
        return values;
    }

    private void collectValue(double v) {
        if (values.length < count + 1) {
            values = ArrayUtil.grow(values, count + 1);
        }
        values[count++] = v;
    }

    public static class Value {
        private final DoubleScriptFieldScript script;

        public Value(DoubleScriptFieldScript script) {
            this.script = script;
        }

        public void value(double v) {
            script.collectValue(v);
        }
    }
}
