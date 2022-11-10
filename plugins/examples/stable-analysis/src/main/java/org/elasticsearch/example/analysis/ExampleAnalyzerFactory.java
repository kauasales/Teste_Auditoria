/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.example.analysis;

import org.apache.lucene.analysis.Analyzer;
import org.elasticsearch.example.analysis.lucene.CharTokenizer;
import org.elasticsearch.example.analysis.lucene.ReplaceCharToNumber;
import org.elasticsearch.example.analysis.lucene.SkipTokenFilter;
import org.elasticsearch.plugin.api.NamedComponent;
import org.elasticsearch.plugin.api.settings.InjectSettings;

import java.util.List;

@NamedComponent( "example_analyzer_factory")
public class ExampleAnalyzerFactory implements org.elasticsearch.plugin.analysis.api.AnalyzerFactory {
    private final ExampleAnalysisSettings settings;

    @InjectSettings
    public ExampleAnalyzerFactory(ExampleAnalysisSettings settings) {
        this.settings = settings;
    }

    @Override
    //TODO guide lucene
    public Analyzer create() {
        return new CustomAnalyzer(settings);
    }

    static class CustomAnalyzer extends Analyzer {

        private final ExampleAnalysisSettings settings;

        public CustomAnalyzer(ExampleAnalysisSettings settings) {
            this.settings = settings;
        }

        @Override
        protected TokenStreamComponents createComponents(String fieldName) {
            var tokenizerListOfChars = settings.tokenizerListOfChars().isEmpty() ? List.of("_") : settings.tokenizerListOfChars();
            var tokenizer = new CharTokenizer(tokenizerListOfChars);

            long tokenFilterNumber = settings.analyzerUseTokenListOfChars() ? settings.tokenFilterNumber() : -1;
            var tokenFilter = new SkipTokenFilter(tokenizer, tokenFilterNumber);
            return new TokenStreamComponents(
                r -> tokenizer.setReader(new ReplaceCharToNumber(r, settings.oldChar(), settings.newNumber())),
                tokenFilter
            );
        }
    }
}

