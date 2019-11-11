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
package org.elasticsearch.gateway;

import com.carrotsearch.hppc.cursors.ObjectCursor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.document.StringField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexNotFoundException;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.SerialMergeScheduler;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.Scorer;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.Weight;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.SetOnce;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.coordination.CoordinationState;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.common.CheckedConsumer;
import org.elasticsearch.common.io.stream.ReleasableBytesStreamOutput;
import org.elasticsearch.common.lease.Releasable;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.index.Index;

import java.io.Closeable;
import java.io.FilterOutputStream;
import java.io.IOError;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.IntPredicate;

public class LucenePersistedStateFactory {
    private static final Logger logger = LogManager.getLogger(LucenePersistedStateFactory.class);
    private static final String CURRENT_TERM_KEY = "current_term";
    private static final String LAST_ACCEPTED_VERSION_KEY = "last_accepted_version";
    private static final String NODE_ID_KEY = "node_id";
    private static final String NODE_VERSION_KEY = "node_version";
    private static final String TYPE_FIELD_NAME = "type";
    private static final String DATA_FIELD_NAME = "data";
    private static final String GLOBAL_TYPE_NAME = "global";
    private static final String INDEX_TYPE_NAME = "index";
    private static final String INDEX_UUID_FIELD_NAME = "index_uuid";

    private final NodeEnvironment nodeEnvironment;
    private final NamedXContentRegistry namedXContentRegistry;
    private final BigArrays bigArrays;

    public LucenePersistedStateFactory(NodeEnvironment nodeEnvironment, NamedXContentRegistry namedXContentRegistry, BigArrays bigArrays) {
        this.nodeEnvironment = nodeEnvironment;
        this.namedXContentRegistry = namedXContentRegistry;
        this.bigArrays = bigArrays;
    }

    CoordinationState.PersistedState loadPersistedState(BiFunction<Long, MetaData, ClusterState> clusterStateFromMetaData)
        throws IOException {

        final OnDiskState onDiskState = loadBestOnDiskState();

        final List<MetaDataIndex> metaDataIndices = new ArrayList<>();
        final List<Closeable> closeables = new ArrayList<>();
        boolean success = false;
        try {
            for (final Path path : nodeEnvironment.nodeDataPaths()) {
                final Directory directory = createDirectory(getMetaDataIndexPath(path, Version.CURRENT.major));
                closeables.add(directory);

                final IndexWriterConfig indexWriterConfig = new IndexWriterConfig(new KeywordAnalyzer());
                // start empty since we re-write the whole cluster state to ensure it is all using the same format version
                indexWriterConfig.setOpenMode(IndexWriterConfig.OpenMode.CREATE);
                // only commit when specifically instructed, we must not write any intermediate states
                indexWriterConfig.setCommitOnClose(false);
                // most of the data goes into stored fields which are not buffered, so we only really need a tiny buffer
                indexWriterConfig.setRAMBufferSizeMB(1.0);
                // TODO TBD do we want background merging?
                indexWriterConfig.setMergeScheduler(new SerialMergeScheduler());

                final IndexWriter indexWriter = new IndexWriter(directory, indexWriterConfig);
                closeables.add(indexWriter);
                metaDataIndices.add(new MetaDataIndex(directory, indexWriter));
            }
            success = true;
        } finally {
            if (success == false) {
                IOUtils.closeWhileHandlingException(closeables);
            }
        }

        final ClusterState clusterState = clusterStateFromMetaData.apply(onDiskState.lastAcceptedVersion, onDiskState.metaData);
        final LucenePersistedState lucenePersistedState
            = new LucenePersistedState(nodeEnvironment.nodeId(), metaDataIndices, onDiskState.currentTerm, clusterState, bigArrays);
        success = false;
        try {
            lucenePersistedState.persistInitialState();

            for (final Path path : nodeEnvironment.nodeDataPaths()) {
                assert Files.exists(getMetaDataIndexPath(path, Version.CURRENT.major - 1)) == false;
            }
            success = true;
            return lucenePersistedState;
        } finally {
            if (success == false) {
                IOUtils.closeWhileHandlingException(lucenePersistedState);
            }
        }
    }

    // exposed for tests
    Directory createDirectory(Path path) throws IOException {
        return FSDirectory.open(path);
    }

    private static class OnDiskState {
        final String nodeId;
        final long currentTerm;
        final long lastAcceptedVersion;
        final MetaData metaData;

        private OnDiskState(String nodeId, long currentTerm, long lastAcceptedVersion, MetaData metaData) {
            this.nodeId = nodeId;
            this.currentTerm = currentTerm;
            this.lastAcceptedVersion = lastAcceptedVersion;
            this.metaData = metaData;
        }
    }

    private OnDiskState loadBestOnDiskState() throws IOException {
        long maxCurrentTerm = 0L;
        String committedClusterUuid = null;
        OnDiskState bestOnDiskState = new OnDiskState(null, 0L, 0L, MetaData.EMPTY_META_DATA);

        // We use a write-all-read-one strategy: metadata is written to every data path when accepting it, which means it is mostly
        // sufficient to read _any_ copy. "Mostly" sufficient because the user can change the set of data paths when restarting, and may
        // add a data path containing a stale copy of the metadata. We deal with this by using the freshest copy we can find.
        for (final Path dataPath : nodeEnvironment.nodeDataPaths()) {
            for (int majorVersion = Version.CURRENT.major - 1; majorVersion <= Version.CURRENT.major; majorVersion++) {
                final Path indexPath = getMetaDataIndexPath(dataPath, majorVersion);
                if (Files.exists(indexPath)) {
                    try (Directory directory = createDirectory(indexPath);
                         DirectoryReader directoryReader = DirectoryReader.open(directory)) {
                        final OnDiskState onDiskState = loadOnDiskState(directoryReader);

                        if (nodeEnvironment.nodeId().equals(onDiskState.nodeId) == false) {
                            throw new IllegalStateException("unexpected node ID in metadata, found [" + onDiskState.nodeId +
                                "] but expected [" + nodeEnvironment.nodeId() + "]");
                        }

                        if (onDiskState.metaData.clusterUUIDCommitted()) {
                            if (committedClusterUuid == null) {
                                committedClusterUuid = onDiskState.metaData.clusterUUID();
                            } else if (committedClusterUuid.equals(onDiskState.metaData.clusterUUID()) == false) {
                                throw new IllegalStateException("mismatched cluster UUIDs in metadata, found [" + committedClusterUuid +
                                    "] and [" + onDiskState.metaData.clusterUUID() +
                                    "]");
                            }
                        }

                        maxCurrentTerm = Math.max(maxCurrentTerm, onDiskState.currentTerm);

                        long acceptedTerm = onDiskState.metaData.coordinationMetaData().term();
                        long maxAcceptedTerm = bestOnDiskState.metaData.coordinationMetaData().term();
                        if (acceptedTerm > maxAcceptedTerm
                            || (acceptedTerm == maxAcceptedTerm
                                && (onDiskState.lastAcceptedVersion > bestOnDiskState.lastAcceptedVersion
                                    || (onDiskState.lastAcceptedVersion == bestOnDiskState.lastAcceptedVersion)
                                        && onDiskState.currentTerm > bestOnDiskState.currentTerm))) {
                            bestOnDiskState = onDiskState;
                        }
                    } catch (IndexNotFoundException e) {
                        logger.debug(new ParameterizedMessage("no on-disk state at {}", indexPath), e);
                    }
                }
            }
        }

        if (bestOnDiskState.currentTerm != maxCurrentTerm) {
            throw new IllegalStateException("inconsistent terms found: best state is in term [" + bestOnDiskState.currentTerm +
                "] but there is a stale state with greater term [" + maxCurrentTerm + "]");
        }

        return bestOnDiskState;
    }

    private static Path getMetaDataIndexPath(Path path, int majorVersion) {
        return path.resolve(getMetaDataIndexDirectoryName(majorVersion));
    }

    public static String getMetaDataIndexDirectoryName(int majorVersion) {
        // include the version in the directory name to create a completely new index when upgrading to the next major version.
        return "_metadata_v" + majorVersion;
    }

    private OnDiskState loadOnDiskState(DirectoryReader reader) throws IOException {
        final IndexSearcher searcher = new IndexSearcher(reader);
        searcher.setQueryCache(null);

        final SetOnce<MetaData.Builder> builderReference = new SetOnce<>();
        consumeFromType(searcher, GLOBAL_TYPE_NAME, bytes ->
        {
            final MetaData metaData = MetaData.fromXContent(XContentFactory.xContent(XContentType.SMILE)
                .createParser(namedXContentRegistry, LoggingDeprecationHandler.INSTANCE, bytes.bytes, bytes.offset, bytes.length));
            logger.trace("found global metadata with last-accepted term [{}]", metaData.coordinationMetaData().term());
            builderReference.set(MetaData.builder(metaData));
        });

        final MetaData.Builder builder = builderReference.get();
        assert builder != null : "no global metadata found";

        logger.trace("got global metadata, now reading index metadata");

        final Set<String> indexUUIDsForAssertions = new HashSet<>();
        consumeFromType(searcher, INDEX_TYPE_NAME, bytes ->
        {
            final IndexMetaData indexMetaData = IndexMetaData.fromXContent(XContentFactory.xContent(XContentType.SMILE)
                .createParser(namedXContentRegistry, LoggingDeprecationHandler.INSTANCE, bytes.bytes, bytes.offset, bytes.length));
            logger.trace("found index metadata for {}", indexMetaData.getIndex());
            //noinspection AssertWithSideEffects
            assert indexUUIDsForAssertions.add(indexMetaData.getIndexUUID());
            builder.put(indexMetaData, false);
        });

        final Map<String, String> userData = reader.getIndexCommit().getUserData();
        logger.trace("loaded metadata [{}] from [{}]", userData, reader.directory());
        assert userData.size() == 4 : userData;
        assert userData.get(CURRENT_TERM_KEY) != null;
        assert userData.get(LAST_ACCEPTED_VERSION_KEY) != null;
        assert userData.get(NODE_ID_KEY) != null;
        assert userData.get(NODE_VERSION_KEY) != null;
        return new OnDiskState(userData.get(NODE_ID_KEY), Long.parseLong(userData.get(CURRENT_TERM_KEY)),
            Long.parseLong(userData.get(LAST_ACCEPTED_VERSION_KEY)), builder.build());
    }

    private static void consumeFromType(IndexSearcher indexSearcher, String type,
                                        CheckedConsumer<BytesRef, IOException> bytesRefConsumer) throws IOException {

        final Query query = new TermQuery(new Term(TYPE_FIELD_NAME, type));
        final Weight weight = indexSearcher.createWeight(query, ScoreMode.COMPLETE_NO_SCORES, 0.0f);
        logger.trace("running query [{}]", query);

        for (LeafReaderContext leafReaderContext : indexSearcher.getIndexReader().leaves()) {
            logger.trace("new leafReaderContext: {}", leafReaderContext);
            final Scorer scorer = weight.scorer(leafReaderContext);
            if (scorer != null) {
                final Bits liveDocs = leafReaderContext.reader().getLiveDocs();
                final IntPredicate isLiveDoc = liveDocs == null ? i -> true : liveDocs::get;
                final DocIdSetIterator docIdSetIterator = scorer.iterator();
                while (docIdSetIterator.nextDoc() != DocIdSetIterator.NO_MORE_DOCS) {
                    if (isLiveDoc.test(docIdSetIterator.docID())) {
                        logger.trace("processing doc {}", docIdSetIterator.docID());
                        bytesRefConsumer.accept(
                            leafReaderContext.reader().document(docIdSetIterator.docID()).getBinaryValue(DATA_FIELD_NAME));
                    }
                }
            }
        }
    }

    private static final ToXContent.Params FORMAT_PARAMS;

    static {
        Map<String, String> params = new HashMap<>(2);
        params.put("binary", "true");
        params.put(MetaData.CONTEXT_MODE_PARAM, MetaData.CONTEXT_MODE_GATEWAY);
        FORMAT_PARAMS = new ToXContent.MapParams(params);
    }

    /**
     * A {@link Document} with a stored field containing serialized metadata written to a {@link ReleasableBytesStreamOutput} which must be
     * released when no longer needed.
     */
    private static class ReleasableDocument implements Releasable {
        private final Document document;
        private final Releasable releasable;

        ReleasableDocument(Document document, Releasable releasable) {
            this.document = document;
            this.releasable = releasable;
        }

        Document getDocument() {
            return document;
        }

        @Override
        public void close() {
            releasable.close();
        }
    }

    /**
     * Encapsulates a single {@link IndexWriter}. There is one of these for each data path.
     */
    private static class MetaDataIndex implements Closeable {

        private final Logger logger;
        private final Directory directory;
        private final IndexWriter indexWriter;

        MetaDataIndex(Directory directory, IndexWriter indexWriter) {
            this.directory = directory;
            this.indexWriter = indexWriter;
            this.logger = Loggers.getLogger(MetaDataIndex.class, directory.toString());
        }

        void deleteAll() throws IOException {
            this.logger.trace("clearing existing metadata");
            this.indexWriter.deleteAll();
        }

        void addIndexMetaDataDocument(Document indexMetaDataDocument, Index index) throws IOException {
            this.logger.trace("adding index metadata doc for [{}]", index);
            indexWriter.addDocument(indexMetaDataDocument);
        }

        void addGlobalMetaData(Document globalMetaDataDocument) throws IOException {
            this.logger.trace("adding global metadata doc");
            indexWriter.addDocument(globalMetaDataDocument);
        }

        void deleteGlobalMetaData() throws IOException {
            indexWriter.deleteDocuments(new Term(TYPE_FIELD_NAME, GLOBAL_TYPE_NAME));
        }

        void deleteIndexMetaData(String indexUUID) throws IOException {
            this.logger.trace("removing metadata for [{}]", indexUUID);
            indexWriter.deleteDocuments(new Term(INDEX_UUID_FIELD_NAME, indexUUID));
        }

        void flush() throws IOException {
            this.logger.trace("flushing");
            this.indexWriter.flush();
        }

        void commit(String nodeId, long currentTerm, long lastAcceptedVersion) throws IOException {
            final Map<String, String> commitData = new HashMap<>(2);
            commitData.put(CURRENT_TERM_KEY, Long.toString(currentTerm));
            commitData.put(LAST_ACCEPTED_VERSION_KEY, Long.toString(lastAcceptedVersion));
            commitData.put(NODE_VERSION_KEY, Integer.toString(Version.CURRENT.id));
            commitData.put(NODE_ID_KEY, nodeId);
            indexWriter.setLiveCommitData(commitData.entrySet());
            indexWriter.commit();
        }

        @Override
        public void close() throws IOException {
            IOUtils.close(indexWriter, directory);
        }
    }

    /**
     * Encapsulates the incremental writing of metadata to a collection of {@link MetaDataIndex}es.
     */
    private static class LucenePersistedState implements CoordinationState.PersistedState, Closeable {

        private long currentTerm;
        private ClusterState lastAcceptedState;
        private final List<MetaDataIndex> metaDataIndices;
        private final String nodeId;
        private final BigArrays bigArrays;

        LucenePersistedState(String nodeId, List<MetaDataIndex> metaDataIndices, long currentTerm, ClusterState lastAcceptedState,
                             BigArrays bigArrays) {
            this.currentTerm = currentTerm;
            this.lastAcceptedState = lastAcceptedState;
            this.metaDataIndices = metaDataIndices;
            this.nodeId = nodeId;
            this.bigArrays = bigArrays;
        }

        @Override
        public long getCurrentTerm() {
            return currentTerm;
        }

        @Override
        public ClusterState getLastAcceptedState() {
            return lastAcceptedState;
        }

        void persistInitialState() throws IOException {
            // Write the whole state out to be sure it's fresh and using the latest format. Called during initialisation, so that
            // (1) throwing an IOException is enough to halt the node, and
            // (2) the index is currently empty since it was opened with IndexWriterConfig.OpenMode.CREATE

            // In the common case it's actually sufficient to commit() the existing state and not do any indexing. For instance, this is
            // true if there's only one data path on this master node, and the commit we just loaded was already written out by this
            // version of Elasticsearch. TODO TBD should we avoid indexing when possible?
            addMetaData(lastAcceptedState);
            commit(currentTerm, lastAcceptedState.getVersion());
        }

        @Override
        public void setCurrentTerm(long currentTerm) {
            commit(currentTerm, lastAcceptedState.version());
            this.currentTerm = currentTerm;
        }

        @Override
        public void setLastAcceptedState(ClusterState clusterState) {
            try {
                if (clusterState.term() != lastAcceptedState.term()) {
                    assert clusterState.term() > lastAcceptedState.term() : clusterState.term() + " vs " + lastAcceptedState.term();
                    // In a new currentTerm, we cannot compare the persisted metadata's lastAcceptedVersion to those in the new state, so
                    // it's simplest to write everything again.
                    overwriteMetaData(clusterState);
                } else {
                    // Within the same currentTerm, we _can_ use metadata versions to skip unnecessary writing.
                    updateMetaData(clusterState);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            commit(currentTerm, clusterState.version());
            lastAcceptedState = clusterState;
        }

        /**
         * Update the persisted metadata to match the given cluster state by removing any stale or unnecessary documents and adding any
         * updated documents.
         */
        private void updateMetaData(ClusterState clusterState) throws IOException {
            assert lastAcceptedState.term() == clusterState.term();
            logger.trace("currentTerm [{}] matches previous currentTerm, writing changes only", clusterState.term());

            try (ReleasableDocument globalMetaDataDocument = makeGlobalMetadataDocument(clusterState)) {
                for (MetaDataIndex metaDataIndex : metaDataIndices) {
                    metaDataIndex.deleteGlobalMetaData();
                    metaDataIndex.addGlobalMetaData(globalMetaDataDocument.getDocument());
                }
            }

            final Map<String, Long> indexMetadataVersionByUUID = new HashMap<>(lastAcceptedState.metaData().indices().size());
            for (ObjectCursor<IndexMetaData> cursor : lastAcceptedState.metaData().indices().values()) {
                final IndexMetaData indexMetaData = cursor.value;
                final Long previousValue = indexMetadataVersionByUUID.putIfAbsent(indexMetaData.getIndexUUID(), indexMetaData.getVersion());
                assert previousValue == null : indexMetaData.getIndexUUID() + " already mapped to " + previousValue;
            }

            for (ObjectCursor<IndexMetaData> cursor : clusterState.metaData().indices().values()) {
                final IndexMetaData indexMetaData = cursor.value;
                final Long previousVersion = indexMetadataVersionByUUID.get(indexMetaData.getIndexUUID());
                if (previousVersion == null || indexMetaData.getVersion() != previousVersion) {
                    if (previousVersion != null) {
                        logger.trace("overwriting metadata for [{}], changing lastAcceptedVersion from [{}] to [{}]",
                            indexMetaData.getIndex(), previousVersion, indexMetaData.getVersion());
                        for (MetaDataIndex metaDataIndex : metaDataIndices) {
                            metaDataIndex.deleteIndexMetaData(indexMetaData.getIndexUUID());
                        }
                    } else {
                        logger.trace("writing metadata for new [{}]", indexMetaData.getIndex());
                    }

                    try (ReleasableDocument indexMetaDataDocument = makeIndexMetadataDocument(indexMetaData)) {
                        for (MetaDataIndex metaDataIndex : metaDataIndices) {
                            metaDataIndex.addIndexMetaDataDocument(indexMetaDataDocument.getDocument(), indexMetaData.getIndex());
                        }
                    }
                } else {
                    logger.trace("no action required for [{}]", indexMetaData.getIndex());
                }
                indexMetadataVersionByUUID.remove(indexMetaData.getIndexUUID());
            }

            for (String removedIndexUUID : indexMetadataVersionByUUID.keySet()) {
                for (MetaDataIndex metaDataIndex : metaDataIndices) {
                    metaDataIndex.deleteIndexMetaData(removedIndexUUID);
                }
            }

            // Flush, to try and expose a failure (e.g. out of disk space) before committing, because we can handle a failure here more
            // gracefully than one that occurs during the commit process.
            for (MetaDataIndex metaDataIndex : metaDataIndices) {
                metaDataIndex.flush();
            }
        }

        /**
         * Update the persisted metadata to match the given cluster state by removing all existing documents and then adding new documents.
         */
        private void overwriteMetaData(ClusterState clusterState) throws IOException {
            for (MetaDataIndex metaDataIndex : metaDataIndices) {
                metaDataIndex.deleteAll();
            }
            addMetaData(clusterState);
        }

        /**
         * Add documents for the metadata of the given cluster state, assuming that there are currently no documents.
         */
        private void addMetaData(ClusterState clusterState) throws IOException {
            try (ReleasableDocument globalMetaDataDocument = makeGlobalMetadataDocument(clusterState)) {
                for (MetaDataIndex metaDataIndex : metaDataIndices) {
                    metaDataIndex.addGlobalMetaData(globalMetaDataDocument.getDocument());
                }
            }

            for (ObjectCursor<IndexMetaData> cursor : clusterState.metaData().indices().values()) {
                final IndexMetaData indexMetaData = cursor.value;
                try (ReleasableDocument indexMetaDataDocument = makeIndexMetadataDocument(indexMetaData)) {
                    for (MetaDataIndex metaDataIndex : metaDataIndices) {
                        metaDataIndex.addIndexMetaDataDocument(indexMetaDataDocument.getDocument(), indexMetaData.getIndex());
                    }
                }
            }

            // Flush, to try and expose a failure (e.g. out of disk space) before committing, because we can handle a failure here more
            // gracefully than one that occurs during the commit process.
            for (MetaDataIndex metaDataIndex : metaDataIndices) {
                metaDataIndex.flush();
            }
        }

        private void commit(long currentTerm, long lastAcceptedVersion) {
            try {
                for (MetaDataIndex metaDataIndex : metaDataIndices) {
                    metaDataIndex.commit(nodeId, currentTerm, lastAcceptedVersion);
                }
            } catch (IOException e) {
                // The commit() call has similar semantics to a fsync(): although it's atomic, if it fails then we've no idea whether the
                // data on disk is now the old version or the new version, and this is a disaster. It's safest to fail the whole node and
                // retry from the beginning.
                throw new IOError(e);
            }
        }

        @Override
        public void close() throws IOException {
            logger.trace("closing");
            IOUtils.close(metaDataIndices);
        }

        private ReleasableDocument makeIndexMetadataDocument(IndexMetaData indexMetaData) throws IOException {
            final ReleasableDocument indexMetaDataDocument = makeDocument(INDEX_TYPE_NAME, indexMetaData);
            boolean success = false;
            try {
                final String indexUUID = indexMetaData.getIndexUUID();
                assert indexUUID.equals(IndexMetaData.INDEX_UUID_NA_VALUE) == false;
                indexMetaDataDocument.getDocument().add(new StringField(INDEX_UUID_FIELD_NAME, indexUUID, Field.Store.NO));
                success = true;
                return indexMetaDataDocument;
            } finally {
                if (success == false) {
                    IOUtils.closeWhileHandlingException(indexMetaDataDocument);
                }
            }
        }

        private ReleasableDocument makeGlobalMetadataDocument(ClusterState clusterState) throws IOException {
            return makeDocument(GLOBAL_TYPE_NAME, clusterState.metaData());
        }

        private ReleasableDocument makeDocument(String typeName, ToXContent metaData) throws IOException {
            final Document document = new Document();
            document.add(new StringField(TYPE_FIELD_NAME, typeName, Field.Store.NO));

            boolean success = false;
            final ReleasableBytesStreamOutput releasableBytesStreamOutput = new ReleasableBytesStreamOutput(bigArrays);
            try {
                final FilterOutputStream outputStream = new FilterOutputStream(releasableBytesStreamOutput) {
                    @Override
                    public void close() {
                        // closing the XContentBuilder should not release the bytes yet
                    }
                };
                try (XContentBuilder xContentBuilder = XContentFactory.contentBuilder(XContentType.SMILE, outputStream)) {
                    xContentBuilder.startObject();
                    metaData.toXContent(xContentBuilder, FORMAT_PARAMS);
                    xContentBuilder.endObject();
                }
                document.add(new StoredField(DATA_FIELD_NAME, releasableBytesStreamOutput.bytes().toBytesRef()));
                final ReleasableDocument releasableDocument = new ReleasableDocument(document, releasableBytesStreamOutput);
                success = true;
                return releasableDocument;
            } finally {
                if (success == false) {
                    IOUtils.closeWhileHandlingException(releasableBytesStreamOutput);
                }
            }
        }
    }
}
