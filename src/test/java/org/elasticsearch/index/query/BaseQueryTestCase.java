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

package org.elasticsearch.index.query;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.inject.Injector;
import org.elasticsearch.common.inject.ModulesBuilder;
import org.elasticsearch.common.inject.util.Providers;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsModule;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.EnvironmentModule;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexNameModule;
import org.elasticsearch.index.analysis.AnalysisModule;
import org.elasticsearch.index.cache.IndexCacheModule;
import org.elasticsearch.index.query.functionscore.FunctionScoreModule;
import org.elasticsearch.index.settings.IndexSettingsModule;
import org.elasticsearch.index.similarity.SimilarityModule;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.indices.breaker.NoneCircuitBreakerService;
import org.elasticsearch.indices.query.IndicesQueriesModule;
import org.elasticsearch.script.ScriptModule;
import org.elasticsearch.test.ElasticsearchTestCase;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.threadpool.ThreadPoolModule;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.Matchers.is;

@Ignore
public abstract class BaseQueryTestCase<T extends BaseQueryBuilder> extends ElasticsearchTestCase {

    private Injector injector;
    private IndexQueryParserService queryParserService;
    private Index index;
    protected QueryParseContext context;
    protected XContentParser parser;

    protected T testQuery;

    @Before
    public void init() throws IOException {
        Settings settings = ImmutableSettings.settingsBuilder()
                .put("name", getClass().getName())
                .put(IndexMetaData.SETTING_VERSION_CREATED, Version.CURRENT)
                .build();

        index = new Index("test");
        injector = new ModulesBuilder().add(
                new EnvironmentModule(new Environment(settings)),
                new SettingsModule(settings),
                new ThreadPoolModule(settings),
                new IndicesQueriesModule(),
                new ScriptModule(settings),
                new IndexSettingsModule(index, settings),
                new IndexCacheModule(settings),
                new AnalysisModule(settings),
                new SimilarityModule(settings),
                new IndexNameModule(index),
                new IndexQueryParserModule(settings),
                new FunctionScoreModule(),
                new AbstractModule() {
                    @Override
                    protected void configure() {
                        bind(ClusterService.class).toProvider(Providers.of((ClusterService) null));
                        bind(CircuitBreakerService.class).to(NoneCircuitBreakerService.class);
                    }
                }
        ).createInjector();

        queryParserService = injector.getInstance(IndexQueryParserService.class);

        context = new QueryParseContext(index, queryParserService);
        testQuery = createRandomTestQuery();
        String contentString = testQuery.toString();
        parser = XContentFactory.xContent(contentString).createParser(contentString);
        context.reset(parser);
    }

    /**
     * Create a random query for the type that is being tested
     * @return a randomized query
     */
    public abstract T createRandomTestQuery();

    /**
     * Generic test that creates new query from the randomly creates test query from setup
     * and asserts equality on the two queries.
     * @throws IOException
     */
    @Test
    public void testFromXContent() throws IOException {
        @SuppressWarnings("unchecked")
        T newQuery = (T) queryParserService.queryParser(testQuery.parserName()).fromXContent(context);
        assertNotSame(newQuery, is(testQuery));
        assertThat((T) newQuery, is(testQuery));
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        terminate(injector.getInstance(ThreadPool.class));
    }
}