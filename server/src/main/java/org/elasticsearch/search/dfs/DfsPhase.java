/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.search.dfs;

import org.apache.lucene.index.Term;
import org.apache.lucene.search.CollectionStatistics;
import org.apache.lucene.search.Collector;
import org.apache.lucene.search.CollectorManager;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.TermStatistics;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.TopScoreDocCollector;
import org.elasticsearch.index.query.ParsedQuery;
import org.elasticsearch.index.query.SearchExecutionContext;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.internal.ContextIndexSearcher;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.search.profile.Profilers;
import org.elasticsearch.search.profile.Timer;
import org.elasticsearch.search.profile.dfs.DfsProfiler;
import org.elasticsearch.search.profile.dfs.DfsTimingType;
import org.elasticsearch.search.profile.query.CollectorResult;
import org.elasticsearch.search.profile.query.ProfileCollectorManager;
import org.elasticsearch.search.profile.query.QueryProfiler;
import org.elasticsearch.search.rescore.RescoreContext;
import org.elasticsearch.search.vectors.KnnSearchBuilder;
import org.elasticsearch.search.vectors.KnnVectorQueryBuilder;
import org.elasticsearch.tasks.TaskCancelledException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * DFS phase of a search request, used to make scoring 100% accurate by collecting additional info from each shard before the query phase.
 * The additional information is used to better compare the scores coming from all the shards, which depend on local factors (e.g. idf).
 * When a kNN search is provided alongside the query, the DFS phase is also used to gather the top k candidates from each shard. Then the
 * global top k hits are passed on to the query phase.
 */
public class DfsPhase {

    public void execute(SearchContext context) {
        try {
            collectStatistics(context);
            executeKnnVectorQuery(context);

            if (context.getProfilers() != null) {
                context.dfsResult().profileResult(context.getProfilers().getDfsProfiler().buildDfsPhaseResults());
            }
        } catch (Exception e) {
            throw new DfsPhaseExecutionException(context.shardTarget(), "Exception during dfs phase", e);
        }
    }

    private void collectStatistics(SearchContext context) throws IOException {
        final DfsProfiler profiler = context.getProfilers() == null ? null : context.getProfilers().getDfsProfiler();

        Map<String, CollectionStatistics> fieldStatistics = new HashMap<>();
        Map<Term, TermStatistics> stats = new HashMap<>();

        IndexSearcher searcher = new IndexSearcher(context.searcher().getIndexReader()) {
            @Override
            public TermStatistics termStatistics(Term term, int docFreq, long totalTermFreq) throws IOException {
                if (context.isCancelled()) {
                    throw new TaskCancelledException("cancelled");
                }
                Timer timer = maybeStartTimer(profiler, DfsTimingType.TERM_STATISTICS);
                try {
                    TermStatistics ts = super.termStatistics(term, docFreq, totalTermFreq);
                    if (ts != null) {
                        stats.put(term, ts);
                    }
                    return ts;
                } finally {
                    if (timer != null) {
                        timer.stop();
                    }
                }
            }

            @Override
            public CollectionStatistics collectionStatistics(String field) throws IOException {
                if (context.isCancelled()) {
                    throw new TaskCancelledException("cancelled");
                }
                Timer timer = maybeStartTimer(profiler, DfsTimingType.COLLECTION_STATISTICS);
                try {
                    CollectionStatistics cs = super.collectionStatistics(field);
                    if (cs != null) {
                        fieldStatistics.put(field, cs);
                    }
                    return cs;
                } finally {
                    if (timer != null) {
                        timer.stop();
                    }
                }
            }
        };

        if (profiler != null) {
            profiler.start();
        }

        try {
            Timer timer = maybeStartTimer(profiler, DfsTimingType.CREATE_WEIGHT);
            try {
                searcher.createWeight(context.rewrittenQuery(), ScoreMode.COMPLETE, 1);
            } finally {
                if (timer != null) {
                    timer.stop();
                }
            }
            for (RescoreContext rescoreContext : context.rescore()) {
                for (ParsedQuery parsedQuery : rescoreContext.getParsedQueries()) {
                    final Query rewritten;
                    timer = maybeStartTimer(profiler, DfsTimingType.REWRITE);
                    try {
                        rewritten = searcher.rewrite(parsedQuery.query());
                    } finally {
                        if (timer != null) {
                            timer.stop();
                        }
                    }
                    timer = maybeStartTimer(profiler, DfsTimingType.CREATE_WEIGHT);
                    try {
                        searcher.createWeight(rewritten, ScoreMode.COMPLETE, 1);
                    } finally {
                        if (timer != null) {
                            timer.stop();
                        }
                    }
                }
            }
        } finally {
            if (profiler != null) {
                profiler.stop();
            }
        }

        Term[] terms = stats.keySet().toArray(new Term[0]);
        TermStatistics[] termStatistics = new TermStatistics[terms.length];
        for (int i = 0; i < terms.length; i++) {
            termStatistics[i] = stats.get(terms[i]);
        }

        context.dfsResult()
            .termsStatistics(terms, termStatistics)
            .fieldStatistics(fieldStatistics)
            .maxDoc(context.searcher().getIndexReader().maxDoc());
    }

    /**
     * If profiler isn't null, this returns a started {@link Timer}.
     * Otherwise, returns null.
     */
    private static Timer maybeStartTimer(DfsProfiler profiler, DfsTimingType dtt) {
        if (profiler != null) {
            return profiler.startTimer(dtt);
        }
        return null;
    };

    private void executeKnnVectorQuery(SearchContext context) throws IOException {
        SearchSourceBuilder source = context.request().source();
        if (source == null || source.knnSearch().isEmpty()) {
            return;
        }

        SearchExecutionContext searchExecutionContext = context.getSearchExecutionContext();
        List<KnnSearchBuilder> knnSearch = context.request().source().knnSearch();
        List<KnnVectorQueryBuilder> knnVectorQueryBuilders = knnSearch.stream().map(KnnSearchBuilder::toQueryBuilder).toList();

        if (context.request().getAliasFilter().getQueryBuilder() != null) {
            for (KnnVectorQueryBuilder knnVectorQueryBuilder : knnVectorQueryBuilders) {
                knnVectorQueryBuilder.addFilterQuery(context.request().getAliasFilter().getQueryBuilder());
            }
        }
        List<DfsKnnResults> knnResults = new ArrayList<>(knnVectorQueryBuilders.size());
        for (int i = 0; i < knnSearch.size(); i++) {
            Query knnQuery = searchExecutionContext.toQuery(knnVectorQueryBuilders.get(i)).query();
            knnResults.add(singleKnnSearch(knnQuery, knnSearch.get(i).k(), context.getProfilers(), context.searcher()));
        }
        context.dfsResult().knnResults(knnResults);
    }

    /**
     * @param <C> the type of collector
     * @param <R> the #reduce() return type
     */
    static class CollectorManagerAdapter<C extends Collector, R> implements CollectorManager<C, Void> {

        private final CollectorManager<C, R> wrapped;
        private final Consumer<R> resultConsumer;

        CollectorManagerAdapter(CollectorManager<C, R> in, Consumer<R> resultConsumer) {
            this.wrapped = in;
            this.resultConsumer = resultConsumer;
        }

        @Override
        public C newCollector() throws IOException {
            return wrapped.newCollector();
        }

        @Override
        public Void reduce(Collection<C> collectors) throws IOException {
            resultConsumer.accept(wrapped.reduce(collectors));
            return null;
        }
    }

    static DfsKnnResults singleKnnSearch(Query knnQuery, int k, Profilers profilers, ContextIndexSearcher searcher) throws IOException {
        final TopDocs[] topDocs = new TopDocs[1];
        CollectorManager<? extends Collector, Void> cm = new CollectorManagerAdapter<>(
            TopScoreDocCollector.createSharedManager(k, null, Integer.MAX_VALUE),
            res -> topDocs[0] = res
        );

        if (profilers != null) {
            ProfileCollectorManager ipcm = new ProfileCollectorManager(cm, CollectorResult.REASON_SEARCH_TOP_HITS);
            QueryProfiler knnProfiler = profilers.getDfsProfiler().addQueryProfiler(ipcm);
            cm = ipcm;
            // Set the current searcher profiler to gather query profiling information for gathering top K docs
            searcher.setProfiler(knnProfiler);
        }
        searcher.search(knnQuery, cm);

        // Set profiler back after running KNN searches
        if (profilers != null) {
            searcher.setProfiler(profilers.getCurrentQueryProfiler());
        }
        return new DfsKnnResults(topDocs[0].scoreDocs);
    }
}
