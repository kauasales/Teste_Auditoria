/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.elasticsearch.index.analysis;

import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.index.AbstractIndexComponent;
import org.elasticsearch.index.IndexSettings;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static java.util.Collections.unmodifiableMap;

/**
 * IndexAnalyzers contains a name to analyzer mapping for a specific index.
 * This class only holds analyzers that are explicitly configured for an index and doesn't allow
 * access to individual tokenizers, char or token filter.
 *
 * @see AnalysisRegistry
 */
public final class IndexAnalyzers extends AbstractIndexComponent implements Closeable {
    private final NamedAnalyzer defaultIndexAnalyzer;
    private final NamedAnalyzer defaultSearchAnalyzer;
    private final NamedAnalyzer defaultSearchQuoteAnalyzer;
    private final Map<String, NamedAnalyzer> analyzers;
    private final Map<String, NamedAnalyzer> normalizers;
    private final Map<String, NamedAnalyzer> whitespaceNormalizers;

    public IndexAnalyzers(IndexSettings indexSettings, NamedAnalyzer defaultIndexAnalyzer, NamedAnalyzer defaultSearchAnalyzer,
                          NamedAnalyzer defaultSearchQuoteAnalyzer, Map<String, NamedAnalyzer> analyzers,
                          Map<String, NamedAnalyzer> normalizers, Map<String, NamedAnalyzer> whitespaceNormalizers) {
        super(indexSettings);
        if (defaultIndexAnalyzer.name().equals("default") == false) {
            throw new IllegalStateException("default analyzer must have the name [default] but was: [" + defaultIndexAnalyzer.name() + "]");
        }
        this.defaultIndexAnalyzer = defaultIndexAnalyzer;
        this.defaultSearchAnalyzer = defaultSearchAnalyzer;
        this.defaultSearchQuoteAnalyzer = defaultSearchQuoteAnalyzer;
        this.analyzers =  unmodifiableMap(new HashMap<>(analyzers));
        this.normalizers = unmodifiableMap(new HashMap<>(normalizers));
        this.whitespaceNormalizers = unmodifiableMap(new HashMap<>(whitespaceNormalizers));
    }

    /**
     * Returns an analyzer mapped to the given name or <code>null</code> if not present
     */
    public NamedAnalyzer get(String name) {
        return analyzers.get(name);
    }

    /**
     * Returns an (unmodifiable) map of containing the index analyzers
     */
    Map<String, NamedAnalyzer> getAnalyzers() {
        return analyzers;
    }

    /**
     * Returns a normalizer mapped to the given name or <code>null</code> if not present
     */
    public NamedAnalyzer getNormalizer(String name) {
        return normalizers.get(name);
    }

    /**
     * Returns an (unmodifiable) map of containing the index normalizers
     */
    Map<String, NamedAnalyzer> getNormalizers() {
        return normalizers;
    }

    /**
     * Returns a normalizer that splits on whitespace mapped to the given name or <code>null</code> if not present
     */
    public NamedAnalyzer getWhitespaceNormalizer(String name) {
        return whitespaceNormalizers.get(name);
    }

    /**
     * Returns an (unmodifiable) map of containing the index whitespace normalizers
     */
    Map<String, NamedAnalyzer> getWhitespaceNormalizers() {
        return whitespaceNormalizers;
    }

    /**
     * Returns the default index analyzer for this index
     */
    public NamedAnalyzer getDefaultIndexAnalyzer() {
        return defaultIndexAnalyzer;
    }

    /**
     * Returns the default search analyzer for this index
     */
    public NamedAnalyzer getDefaultSearchAnalyzer() {
        return defaultSearchAnalyzer;
    }

    /**
     * Returns the default search quote analyzer for this index
     */
    public NamedAnalyzer getDefaultSearchQuoteAnalyzer() {
        return defaultSearchQuoteAnalyzer;
    }

    @Override
    public void close() throws IOException {
       IOUtils.close(() -> Stream.concat(analyzers.values().stream(), normalizers.values().stream())
           .filter(a -> a.scope() == AnalyzerScope.INDEX)
           .iterator());
    }
}
