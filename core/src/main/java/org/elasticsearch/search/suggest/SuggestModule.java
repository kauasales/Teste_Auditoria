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
package org.elasticsearch.search.suggest;

import com.google.common.collect.Lists;
import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.inject.multibindings.Multibinder;
import org.elasticsearch.search.suggest.completionv2.CompletionSuggester;
import org.elasticsearch.search.suggest.phrase.PhraseSuggester;
import org.elasticsearch.search.suggest.term.TermSuggester;

import java.util.List;

/**
 *
 */
public class SuggestModule extends AbstractModule {

    private List<Class<? extends Suggester>> suggesters = Lists.newArrayList();

    public SuggestModule() {
        registerSuggester(PhraseSuggester.class);
        registerSuggester(TermSuggester.class);
        registerSuggester(org.elasticsearch.search.suggest.completion.CompletionSuggester.class);
        // added completion V2
        registerSuggester(CompletionSuggester.class);
    }

    public void registerSuggester(Class<? extends Suggester> suggester) {
        suggesters.add(suggester);
    }

    @Override
    protected void configure() {
        Multibinder<Suggester> suggesterMultibinder = Multibinder.newSetBinder(binder(), Suggester.class);
        for (Class<? extends Suggester> clazz : suggesters) {
            suggesterMultibinder.addBinding().to(clazz);
        }

        bind(SuggestParseElement.class).asEagerSingleton();
        bind(SuggestPhase.class).asEagerSingleton();
        bind(Suggesters.class).asEagerSingleton();
    }
}
