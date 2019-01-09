/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.ccr.repository;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.BytesRefIterator;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.lease.Releasable;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.AbstractRefCounted;
import org.elasticsearch.common.util.concurrent.ConcurrentCollections;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.index.engine.Engine;
import org.elasticsearch.index.shard.IndexEventListener;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.IndexShardClosedException;
import org.elasticsearch.index.shard.IndexShardState;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.store.Store;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public class CcrRestoreSourceService extends AbstractLifecycleComponent implements IndexEventListener {

    private static final Logger logger = LogManager.getLogger(CcrRestoreSourceService.class);

    private final Map<String, RestoreContext> onGoingRestores = ConcurrentCollections.newConcurrentMap();
    private final Map<IndexShard, HashSet<String>> sessionsForShard = new HashMap<>();
    private final CopyOnWriteArrayList<Consumer<String>> openSessionListeners = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Consumer<String>> closeSessionListeners = new CopyOnWriteArrayList<>();

    public CcrRestoreSourceService(Settings settings) {
        super(settings);
    }

    @Override
    public synchronized void afterIndexShardClosed(ShardId shardId, @Nullable IndexShard indexShard, Settings indexSettings) {
        if (indexShard != null) {
            HashSet<String> sessions = sessionsForShard.remove(indexShard);
            if (sessions != null) {
                for (String sessionUUID : sessions) {
                    RestoreContext restore = onGoingRestores.remove(sessionUUID);
                    IOUtils.closeWhileHandlingException(restore);
                }
            }
        }
    }

    @Override
    protected void doStart() {

    }

    @Override
    protected void doStop() {

    }

    @Override
    protected synchronized void doClose() throws IOException {
        sessionsForShard.clear();
        IOUtils.closeWhileHandlingException(onGoingRestores.values());
        onGoingRestores.clear();
    }

    // TODO: The listeners are for testing. Once end-to-end file restore is implemented and can be tested,
    //  these should be removed.
    public void addOpenSessionListener(Consumer<String> listener) {
        openSessionListeners.add(listener);
    }

    public void addCloseSessionListener(Consumer<String> listener) {
        closeSessionListeners.add(listener);
    }

    // default visibility for testing
    synchronized HashSet<String> getSessionsForShard(IndexShard indexShard) {
        return sessionsForShard.get(indexShard);
    }

    // default visibility for testing
    synchronized RestoreContext getOngoingRestore(String sessionUUID) {
        return onGoingRestores.get(sessionUUID);
    }

    // TODO: Add a local timeout for the session. This timeout might might be for the entire session to be
    //  complete. Or it could be for session to have been touched.
    public synchronized Store.MetadataSnapshot openSession(String sessionUUID, IndexShard indexShard) throws IOException {
        boolean success = false;
        RestoreContext restore = null;
        try {
            if (onGoingRestores.containsKey(sessionUUID)) {
                logger.debug("not opening new session [{}] as it already exists", sessionUUID);
                restore = onGoingRestores.get(sessionUUID);
            } else {
                logger.debug("opening session [{}] for shard [{}]", sessionUUID, indexShard.shardId());
                if (indexShard.state() == IndexShardState.CLOSED) {
                    throw new IndexShardClosedException(indexShard.shardId(), "cannot open ccr restore session if shard closed");
                }
                restore = new RestoreContext(sessionUUID, indexShard, indexShard.acquireSafeIndexCommit());
                onGoingRestores.put(sessionUUID, restore);
                openSessionListeners.forEach(c -> c.accept(sessionUUID));
                HashSet<String> sessions = sessionsForShard.computeIfAbsent(indexShard, (s) ->  new HashSet<>());
                sessions.add(sessionUUID);
            }
            Store.MetadataSnapshot metaData = restore.getMetaData();
            success = true;
            return metaData;
        } finally {
            if (success ==  false) {
                onGoingRestores.remove(sessionUUID);
                IOUtils.closeWhileHandlingException(restore);
            }
        }
    }

    public synchronized void closeSession(String sessionUUID) {
        closeSessionListeners.forEach(c -> c.accept(sessionUUID));
        RestoreContext restore = onGoingRestores.remove(sessionUUID);
        if (restore == null) {
            logger.info("could not close session [{}] because session not found", sessionUUID);
            throw new IllegalArgumentException("session [" + sessionUUID + "] not found");
        }
        IOUtils.closeWhileHandlingException(restore);
    }

    public synchronized Reader getSessionReader(String sessionUUID, String fileName) throws IOException {
        RestoreContext restore = onGoingRestores.get(sessionUUID);
        if (restore == null) {
            logger.info("could not get session [{}] because session not found", sessionUUID);
            throw new IllegalArgumentException("session [" + sessionUUID + "] not found");
        }
        return restore.getFileReader(fileName);
    }

    private class RestoreContext implements Closeable {

        private final String sessionUUID;
        private final IndexShard indexShard;
        private final RefCountedCloseable<Engine.IndexCommitRef> session;
        private RefCountedCloseable<IndexInput> cachedInput;
        private volatile boolean sessionLocked = false;
        private Releasable lockRelease = () -> sessionLocked = false;

        private RestoreContext(String sessionUUID, IndexShard indexShard, Engine.IndexCommitRef commitRef) {
            this.sessionUUID = sessionUUID;
            this.indexShard = indexShard;
            this.session = new RefCountedCloseable<>("commit-ref", commitRef);
        }

        Store.MetadataSnapshot getMetaData() throws IOException {
            indexShard.store().incRef();
            try {
                return indexShard.store().getMetadata(session.object.getIndexCommit());
            } finally {
                indexShard.store().decRef();
            }
        }

        Reader getFileReader(String fileName) throws IOException {
            if (sessionLocked) {
                throw new IllegalStateException("Session is currently locked by another get file chunk request");
            }
            sessionLocked = true;
            if (cachedInput != null) {
                if (fileName.equals(cachedInput.name)) {
                    return new Reader(session, cachedInput, lockRelease);
                } else {
                    cachedInput.decRef();
                    openNewIndexInput(fileName);
                    return new Reader(session, cachedInput, lockRelease);
                }
            } else {
                openNewIndexInput(fileName);
                return new Reader(session, cachedInput, lockRelease);

            }
        }

        @Override
        public void close() {
            assert Thread.holdsLock(CcrRestoreSourceService.this);
            removeSessionForShard(sessionUUID, indexShard);
            if (cachedInput != null) {
                cachedInput.decRef();
            }
            session.decRef();
        }

        private void openNewIndexInput(String fileName) throws IOException {
            Engine.IndexCommitRef commitRef = session.object;
            IndexInput indexInput = commitRef.getIndexCommit().getDirectory().openInput(fileName, IOContext.READONCE);
            cachedInput = new RefCountedCloseable<>(fileName, indexInput);
        }

        private void removeSessionForShard(String sessionUUID, IndexShard indexShard) {
            logger.debug("closing session [{}] for shard [{}]", sessionUUID, indexShard.shardId());
            HashSet<String> sessions = sessionsForShard.get(indexShard);
            if (sessions != null) {
                sessions.remove(sessionUUID);
                if (sessions.isEmpty()) {
                    sessionsForShard.remove(indexShard);
                }
            }
        }
    }

    private static class RefCountedCloseable<T extends Closeable> extends AbstractRefCounted {

        private final String name;
        private final T object;

        private RefCountedCloseable(String name, T object) {
            super(name);
            this.name = name;
            this.object = object;
        }

        @Override
        protected void closeInternal() {
            IOUtils.closeWhileHandlingException(object);
        }
    }

    public static class Reader implements Closeable {

        private final RefCountedCloseable<Engine.IndexCommitRef> session;
        private final RefCountedCloseable<IndexInput> input;
        private final Releasable lockRelease;

        private Reader(RefCountedCloseable<Engine.IndexCommitRef> session, RefCountedCloseable<IndexInput> input, Releasable lockRelease) {
            this.session = session;
            this.input = input;
            this.lockRelease = lockRelease;
            boolean sessionRefIncremented = false;
            boolean inputRefIncremented = false;
            try {
                session.incRef();
                sessionRefIncremented = true;
                input.incRef();
                inputRefIncremented = true;
            } finally {
                if (sessionRefIncremented == false) {
                    IOUtils.closeWhileHandlingException(lockRelease);
                } else if (inputRefIncremented == false) {
                    IOUtils.closeWhileHandlingException(session::decRef, lockRelease);
                }
            }
        }

        public int readFileBytes(BytesReference reference) throws IOException {
            IndexInput in = input.object;
            BytesRefIterator refIterator = reference.iterator();
            BytesRef ref;
            int bytesWritten = 0;
            while ((ref = refIterator.next()) != null) {
                byte[] refBytes = ref.bytes;
                in.readBytes(refBytes, 0, refBytes.length);
                bytesWritten += ref.length;
            }
            return bytesWritten;
        }

        @Override
        public void close() {
            IOUtils.closeWhileHandlingException(input::decRef, session::decRef, lockRelease);
        }
    }
}
