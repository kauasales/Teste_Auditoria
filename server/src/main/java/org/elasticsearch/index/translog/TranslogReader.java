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

package org.elasticsearch.index.translog;

import org.apache.lucene.store.AlreadyClosedException;
import org.elasticsearch.common.io.Channels;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * an immutable translog filereader
 */
public class TranslogReader extends BaseTranslogReader implements Closeable {
    protected final long length;
    private final int totalOperations;
    private final Checkpoint checkpoint;
    protected final AtomicBoolean closed;

    /**
     * Create a translog writer against the specified translog file channel.
     *
     * @param checkpoint the translog checkpoint
     * @param channel    the translog file channel to open a translog reader against
     * @param path       the path to the translog
     * @param header     the header of the translog file
     */
    TranslogReader(final Checkpoint checkpoint, final FileChannel channel, final Path path, final TranslogHeader header) {
        this(checkpoint, channel, path, header,  new AtomicBoolean(false));
    }

    /**
     * Create a translog writer against the specified translog file channel.
     *
     * @param checkpoint the translog checkpoint
     * @param channel    the translog file channel to open a translog reader against
     * @param path       the path to the translog
     * @param header     the header of the translog file
     *
     */
    TranslogReader(final Checkpoint checkpoint, final FileChannel channel, final Path path, final TranslogHeader header, AtomicBoolean closed) {
        super(checkpoint.generation, channel, path, header);
        this.length = checkpoint.offset;
        this.totalOperations = checkpoint.numOps;
        this.checkpoint = checkpoint;
        this.closed = closed;
    }

    /**
     * Given a file channel, opens a {@link TranslogReader}, taking care of checking and validating the file header.
     *
     * @param channel the translog file channel
     * @param path the path to the translog
     * @param checkpoint the translog checkpoint
     * @param translogUUID the tranlog UUID
     * @return a new TranslogReader
     * @throws IOException if any of the file operations resulted in an I/O exception
     */
    public static TranslogReader open(
            final FileChannel channel, final Path path, final Checkpoint checkpoint, final String translogUUID) throws IOException {
        final TranslogHeader header = TranslogHeader.read(translogUUID, path, channel);
        return new TranslogReader(checkpoint, channel, path, header);
    }

    /**
     * Create a new reader with new checkoint that shares resources with current one
     */
    TranslogReader withNewCheckpoint(final Checkpoint newCheckpoint){
        return new TranslogReader(newCheckpoint, channel, path, header,  closed);
    }

    public long sizeInBytes() {
        return length;
    }

    public int totalOperations() {
        return totalOperations;
    }

    @Override
    final Checkpoint getCheckpoint() {
        return checkpoint;
    }

    /**
     * reads an operation at the given position into the given buffer.
     */
    protected void readBytes(ByteBuffer buffer, long position) throws IOException {
        if (position >= length) {
            throw new EOFException("read requested past EOF. pos [" + position + "] end: [" + length + "]");
        }
        if (position < getFirstOperationOffset()) {
            throw new IOException("read requested before position of first ops. pos [" + position + "] first op on: [" + getFirstOperationOffset() + "]");
        }
        Channels.readFromFileChannelWithEofException(channel, position, buffer);
    }

    @Override
    public final void close() throws IOException {
        if (closed.compareAndSet(false, true)) {
            channel.close();
        }
    }

    protected final boolean isClosed() {
        return closed.get();
    }

    protected void ensureOpen() {
        if (isClosed()) {
            throw new AlreadyClosedException(toString() + " is already closed");
        }
    }
}
