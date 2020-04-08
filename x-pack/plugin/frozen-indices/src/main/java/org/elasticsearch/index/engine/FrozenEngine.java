/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.index.engine;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexCommit;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.SegmentReader;
import org.apache.lucene.index.SoftDeletesDirectoryReaderWrapper;
import org.apache.lucene.search.ReferenceManager;
import org.apache.lucene.store.Directory;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.lucene.Lucene;
import org.elasticsearch.common.lucene.index.ElasticsearchDirectoryReader;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.index.shard.DocsStats;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.concurrent.CountDownLatch;
import java.util.function.Function;

/**
 * This is a stand-alone read-only engine that maintains an index reader that is opened lazily on calls to
 * {@link Engine.Reader#acquireSearcher(String)}. The index reader opened is maintained until there are no reference to it anymore
 * and then releases itself from the engine.
 * This is necessary to for instance release all SegmentReaders after a search phase finishes and reopen them before the next search
 * phase starts.
 * This together with a throttled threadpool (search_throttled) guarantees that at most N frozen shards have a low level index reader
 * open at the same time.
 * The internal reopen of readers is treated like a refresh and refresh listeners are called up-on reopen. This allows to consume refresh
 * stats in order to obtain the number of reopens.
 */
public final class FrozenEngine extends ReadOnlyEngine {
    public static final Setting<Boolean> INDEX_FROZEN = Setting.boolSetting("index.frozen", false, Setting.Property.IndexScope,
        Setting.Property.PrivateIndex);
    private final SegmentsStats segmentsStats;
    private final DocsStats docsStats;
    private volatile ElasticsearchDirectoryReader lastOpenedReader;
    private final ElasticsearchDirectoryReader canMatchReader;

    public FrozenEngine(EngineConfig config) {
        super(config, null, null, true, Function.identity());

        boolean success = false;
        Directory directory = store.directory();
        try (DirectoryReader reader = openDirectory(directory)) {
            // we record the segment stats and doc stats here - that's what the reader needs when it's open and it give the user
            // an idea of what it can save when it's closed
            this.segmentsStats = new SegmentsStats();
            for (LeafReaderContext ctx : reader.getContext().leaves()) {
                SegmentReader segmentReader = Lucene.segmentReader(ctx.reader());
                fillSegmentStats(segmentReader, true, segmentsStats);
            }
            this.docsStats = docsStats(reader);
            final DirectoryReader wrappedReader = new SoftDeletesDirectoryReaderWrapper(reader, Lucene.SOFT_DELETES_FIELD);
            canMatchReader = ElasticsearchDirectoryReader.wrap(
                new RewriteCachingDirectoryReader(directory, wrappedReader.leaves()), config.getShardId());
            success = true;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (success == false) {
                closeNoLock("failed on construction", new CountDownLatch(1));
            }
        }
    }

    @Override
    protected DirectoryReader open(IndexCommit indexCommit) throws IOException {
        // we fake an empty DirectoryReader for the ReadOnlyEngine. this reader is only used
        // to initialize the reference manager and to make the refresh call happy which is essentially
        // a no-op now
        return new DirectoryReader(indexCommit.getDirectory(), new LeafReader[0]) {
            @Override
            protected DirectoryReader doOpenIfChanged() {
                return null;
            }

            @Override
            protected DirectoryReader doOpenIfChanged(IndexCommit commit) {
                return null;
            }

            @Override
            protected DirectoryReader doOpenIfChanged(IndexWriter writer, boolean applyAllDeletes) {
                return null;
            }

            @Override
            public long getVersion() {
                return 0;
            }

            @Override
            public boolean isCurrent() {
                return true; // always current
            }

            @Override
            public IndexCommit getIndexCommit() {
                return indexCommit; // TODO maybe we can return an empty commit?
            }

            @Override
            protected void doClose() {
            }

            @Override
            public CacheHelper getReaderCacheHelper() {
                return null;
            }
        };
    }

    @SuppressForbidden(reason = "we manage references explicitly here")
    private synchronized void onReaderClosed(IndexReader.CacheKey key) {
        // it might look awkward that we have to check here if the keys match but if we concurrently
        // access the lastOpenedReader there might be 2 threads competing for the cached reference in
        // a way that thread 1 counts down the lastOpenedReader reference and before thread 1 can execute
        // the close listener we already open and assign a new reader to lastOpenedReader. In this case
        // the cache key doesn't match and we just ignore it since we use this method only to null out the
        // lastOpenedReader member to ensure resources can be GCed
        if (lastOpenedReader != null && key == lastOpenedReader.getReaderCacheHelper().getKey()) {
            assert lastOpenedReader.getRefCount() == 0;
            lastOpenedReader = null;
        }
    }

    @SuppressForbidden(reason = "we manage references explicitly here")
    private synchronized void closeReader(IndexReader reader) throws IOException {
        reader.decRef();
    }

    private synchronized ElasticsearchDirectoryReader getOrOpenReader() throws IOException {
        ElasticsearchDirectoryReader reader = null;
        boolean success = false;
        try {
            reader = getReader();
            if (reader == null) {
                for (ReferenceManager.RefreshListener listeners : config ().getInternalRefreshListener()) {
                    listeners.beforeRefresh();
                }
                final DirectoryReader dirReader = openDirectory(engineConfig.getStore().directory());
                reader = lastOpenedReader = wrapReader(dirReader, Function.identity());
                processReader(reader);
                reader.getReaderCacheHelper().addClosedListener(this::onReaderClosed);
                for (ReferenceManager.RefreshListener listeners : config().getInternalRefreshListener()) {
                    listeners.afterRefresh(true);
                }
            }
            success = true;
            return reader;
        } finally {
            if (success == false) {
                IOUtils.close(reader);
            }
        }
    }

    @SuppressForbidden(reason = "we manage references explicitly here")
    private synchronized ElasticsearchDirectoryReader getReader() {
        if (lastOpenedReader != null && lastOpenedReader.tryIncRef()) {
            return lastOpenedReader;
        }
        return null;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public Reader acquireReader(Function<Searcher, Searcher> wrapper, SearcherScope scope) throws EngineException {
        store.incRef();
        return new Reader(wrapper) {
            @Override
            @SuppressForbidden(reason = "we manage references explicitly here")
            public Searcher acquireSearcherInternal(String source) {
                try {
                    boolean maybeOpenReader;
                    switch (source) {
                        case "load_seq_no":
                        case "load_version":
                            assert false : "this is a read-only engine";
                        case "doc_stats":
                            assert false : "doc_stats are overwritten";
                        case "refresh_needed":
                            assert false : "refresh_needed is always false";
                        case "segments":
                        case "segments_stats":
                        case "completion_stats":
                        case "can_match": // special case for can_match phase - we use the cached point values reader
                            maybeOpenReader = false;
                            break;
                        default:
                            maybeOpenReader = true;
                    }
                    ElasticsearchDirectoryReader reader = maybeOpenReader ? getOrOpenReader() : getReader();
                    if (reader == null) {
                        if ("can_match".equals(source)) {
                            canMatchReader.incRef();
                            return new Searcher(source, canMatchReader, engineConfig.getSimilarity(), engineConfig.getQueryCache(),
                                engineConfig.getQueryCachingPolicy(), canMatchReader::decRef);
                        } else {
                            ReferenceManager<ElasticsearchDirectoryReader> manager = getReferenceManager(scope);
                            ElasticsearchDirectoryReader acquire = manager.acquire();
                            return new Searcher(source, acquire, engineConfig.getSimilarity(), engineConfig.getQueryCache(),
                                engineConfig.getQueryCachingPolicy(), () -> manager.release(acquire));
                        }
                    } else {
                        return new Searcher(source, reader, engineConfig.getSimilarity(), engineConfig.getQueryCache(),
                            engineConfig.getQueryCachingPolicy(), () -> closeReader(reader));
                    }
                } catch (IOException exc) {
                    throw new UncheckedIOException(exc);
                }
            }

            @Override
            public void close() {
                store.decRef();
            }
        };
    }

    @Override
    public SegmentsStats segmentsStats(boolean includeSegmentFileSizes, boolean includeUnloadedSegments) {
        if (includeUnloadedSegments) {
            final SegmentsStats stats = new SegmentsStats();
            stats.add(this.segmentsStats);
            if (includeSegmentFileSizes == false) {
                stats.clearFileSizes();
            }
            return stats;
        } else {
            return super.segmentsStats(includeSegmentFileSizes, includeUnloadedSegments);
        }

    }

    @Override
    public DocsStats docStats() {
        return docsStats;
    }

    synchronized boolean isReaderOpen() {
        return lastOpenedReader != null;
    } // this is mainly for tests
}
