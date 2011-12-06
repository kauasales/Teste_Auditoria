/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterators;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.fr.FrenchStemFilter;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.assistedinject.Assisted;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.settings.IndexSettings;

import java.util.Set;

/**
 *
 */
public class FrenchStemTokenFilterFactory extends AbstractTokenFilterFactory {

    private final Set<?> exclusions;

    @Inject
    public FrenchStemTokenFilterFactory(Index index, @IndexSettings Settings indexSettings, @Assisted String name, @Assisted Settings settings) {
        super(index, indexSettings, name, settings);
        String[] stemExclusion = settings.getAsArray("stem_exclusion");
        if (stemExclusion.length > 0) {
            this.exclusions = ImmutableSet.copyOf(Iterators.forArray(stemExclusion));
        } else {
            this.exclusions = ImmutableSet.of();
        }
    }

    @Override
    public TokenStream create(TokenStream tokenStream) {
        return new FrenchStemFilter(tokenStream, exclusions);
    }
}