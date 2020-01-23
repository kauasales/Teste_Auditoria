/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.index.store;

import org.apache.lucene.store.BufferedIndexInput;
import org.apache.lucene.store.IndexInput;
import org.elasticsearch.common.blobstore.BlobContainer;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.index.snapshots.blobstore.BlobStoreIndexShardSnapshot.FileInfo;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A {@link SearchableSnapshotIndexInput} instance corresponds to a single file from a Lucene directory that has been snapshotted. Because
 * large Lucene file might be split into multiple parts during the snapshot, {@link SearchableSnapshotIndexInput} requires a
 * {@link FileInfo} object at creation time. This object is used to retrieve the file name and length of the original Lucene file, as well
 * as all the parts (stored as "blobs" in the repository) that composed the file in the snapshot.
 *
 * For example, the following {@link FileInfo}:
 *  [name: __4vdpz_HFQ8CuKjCERX0o2A, numberOfParts: 2, partSize: 997b, partBytes: 997, metadata: name [_0_Asserting_0.pos], length [1413]
 *
 * Indicates that the Lucene file "_0_Asserting_0.pos" has a total length of 1413 and is snapshotted into 2 parts:
 * - __4vdpz_HFQ8CuKjCERX0o2A.part1 of size 997b
 * - __4vdpz_HFQ8CuKjCERX0o2A.part2 of size 416b
 *
 * {@link SearchableSnapshotIndexInput} maintains a global position that indicates the current position in the Lucene file where the
 * next read will occur. In the case of a Lucene file snapshotted into multiple parts, this position is used to identify which part must
 * be read at which position (see {@link #readInternal(byte[], int, int)}. This position is also passed over to cloned and sliced input
 * along with the {@link FileInfo} so that they can also track their reading position.
 */
public class SearchableSnapshotIndexInput extends BufferedIndexInput {

    private final BlobContainer blobContainer;
    private final FileInfo fileInfo;
    private final long offset;
    private final long length;

    private long position;
    private volatile boolean closed;

    // optimisation for the case where we perform a single seek, then read a large block of data sequentially, then close the input
    private volatile long sequentialReadSize;
    private static final long NO_SEQUENTIAL_READ_OPTIMIZATION = 0L;
    private final AtomicReference<StreamForSequentialReads> streamForSequentialReadsRef = new AtomicReference<>();

    SearchableSnapshotIndexInput(final BlobContainer blobContainer, final FileInfo fileInfo, long sequentialReadSize, int bufferSize) {
        this("SearchableSnapshotIndexInput(" + fileInfo.physicalName() + ")", blobContainer, fileInfo, 0L, 0L, fileInfo.length(),
            sequentialReadSize, bufferSize);
    }

    private SearchableSnapshotIndexInput(final String resourceDesc, final BlobContainer blobContainer, final FileInfo fileInfo,
                                         final long position, final long offset, final long length, final long sequentialReadSize,
                                         final int bufferSize) {
        super(resourceDesc, bufferSize);
        this.blobContainer = Objects.requireNonNull(blobContainer);
        this.fileInfo = Objects.requireNonNull(fileInfo);
        this.offset = offset;
        this.length = length;
        this.position = position;
        assert sequentialReadSize >= 0;
        this.sequentialReadSize = sequentialReadSize;
        this.closed = false;
    }

    @Override
    public long length() {
        return length;
    }

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException(toString() + " is closed");
        }
    }

    @Override
    protected void readInternal(byte[] b, int offset, int length) throws IOException {
        ensureOpen();
        if (fileInfo.numberOfParts() == 1L) {
            readInternalBytes(0, position, b, offset, length);
        } else {
            int len = length;
            int off = offset;
            while (len > 0) {
                int currentPart = Math.toIntExact(position / fileInfo.partSize().getBytes());
                int remainingBytesInPart;
                if (currentPart < (fileInfo.numberOfParts() - 1)) {
                    remainingBytesInPart = Math.toIntExact(((currentPart + 1L) * fileInfo.partSize().getBytes()) - position);
                } else {
                    remainingBytesInPart = Math.toIntExact(fileInfo.length() - position);
                }
                final int read = Math.min(len, remainingBytesInPart);
                readInternalBytes(currentPart, position % fileInfo.partSize().getBytes(), b, off, read);
                len -= read;
                off += read;
            }
        }
    }

    private void readInternalBytes(final int part, long pos, final byte[] b, int offset, int length) throws IOException {
        final long currentSequentialReadSize = sequentialReadSize;
        if (currentSequentialReadSize != NO_SEQUENTIAL_READ_OPTIMIZATION) {
            final StreamForSequentialReads streamForSequentialReads = streamForSequentialReadsRef.get();
            if (streamForSequentialReads == null) {
                // start a new sequential read
                if (tryReadAndKeepStreamOpen(part, pos, b, offset, length, currentSequentialReadSize)) {
                    return;
                }
            } else if (streamForSequentialReads.part == part && streamForSequentialReads.pos == pos) {
                // continuing a sequential read that we started previously
                assert streamForSequentialReads.isFullyRead() == false;
                int read = streamForSequentialReads.inputStream.read(b, offset, length);
                assert read <= length : read + " vs " + length;
                streamForSequentialReads.pos += read;
                position += read;
                pos += read;
                offset += read;
                length -= read;

                if (streamForSequentialReads.isFullyRead()) {
                    if (streamForSequentialReadsRef.compareAndSet(streamForSequentialReads, null)) {
                        streamForSequentialReads.close();
                    } else {
                        // something happened concurrently, defensively stop optimizing
                        sequentialReadSize = NO_SEQUENTIAL_READ_OPTIMIZATION;
                    }

                    if (length == 0) {
                        // the current stream contained precisely enough data for this read, so we're good.
                        return;
                    } else {
                        // the current stream didn't contain enough data for this read, so we must read more
                        if (sequentialReadSize != NO_SEQUENTIAL_READ_OPTIMIZATION
                            && tryReadAndKeepStreamOpen(part, pos, b, offset, length, currentSequentialReadSize)) {
                            return;
                        }
                    }
                } else {
                    // the current stream contained enough data for this read and more besides, so we leave it alone.
                    assert length == 0 : length + " remaining";
                    return;
                }
            } else {
                // not a sequential read, so stop optimizing for this usage pattern and fall through to the unoptimized behaviour
                assert streamForSequentialReads.isFullyRead() == false;
                sequentialReadSize = NO_SEQUENTIAL_READ_OPTIMIZATION;
                IOUtils.close(streamForSequentialReadsRef.getAndSet(null));
            }
        }

        // read part of a blob directly; the code above falls through to this case where there is no optimization possible
        try (InputStream inputStream = blobContainer.readBlob(fileInfo.partName(part), pos, length)) {
            final int read = inputStream.read(b, offset, length);
            assert read == length : read + " vs " + length;
            position += read;
        }
    }

    /**
     * If appropriate, open a new stream for sequential reading and satisfy the given read using it. Returns whether this happened or not;
     * if it did not happen then nothing was read, and the caller should perform the read directly.
     */
    private boolean tryReadAndKeepStreamOpen(int part, long pos, byte[] b, int offset, int length, long currentSequentialReadSize)
        throws IOException {

        assert streamForSequentialReadsRef.get() == null : "should only be called when a new stream is needed";
        assert currentSequentialReadSize > 0L : "should only be called if optimizing sequential reads";

        final long streamLength = Math.min(currentSequentialReadSize, fileInfo.partBytes(part) - pos);
        if (length < streamLength) {
            // if we open a stream of length streamLength then it will not be completely consumed by this read, so it is worthwhile to open
            // it and keep it open for future reads
            final InputStream inputStream = blobContainer.readBlob(fileInfo.partName(part), pos, streamLength);
            final StreamForSequentialReads newStreamForSequentialReads
                = new StreamForSequentialReads(inputStream, part, pos, streamLength);
            if (streamForSequentialReadsRef.compareAndSet(null, newStreamForSequentialReads) == false) {
                // something happened concurrently, defensively stop optimizing and fall through to the unoptimized behaviour
                this.sequentialReadSize = NO_SEQUENTIAL_READ_OPTIMIZATION;
                inputStream.close();
                return false;
            }

            final int read = newStreamForSequentialReads.inputStream.read(b, offset, length);
            assert read == length : read + " vs " + length;
            position += read;
            newStreamForSequentialReads.pos += read;
            assert newStreamForSequentialReads.isFullyRead() == false;
            return true;
        } else {
            // streamLength <= length so this single read will consume the entire stream, so there is no need to keep hold of it, so we can
            // tell the caller to read the data directly
            return false;
        }
    }

    @Override
    protected void seekInternal(long pos) throws IOException {
        if (pos > length) {
            throw new EOFException("Reading past end of file [position=" + pos + ", length=" + length + "] for " + toString());
        } else if (pos < 0L) {
            throw new IOException("Seeking to negative position [" + pos + "] for " + toString());
        }
        if (position != offset + pos) {
            position = offset + pos;
            IOUtils.close(streamForSequentialReadsRef.getAndSet(null));
        }
    }

    @Override
    public BufferedIndexInput clone() {
        return new SearchableSnapshotIndexInput("clone(" + this + ")", blobContainer, fileInfo, position, offset, length,
            NO_SEQUENTIAL_READ_OPTIMIZATION, getBufferSize());
    }

    @Override
    public IndexInput slice(String sliceDescription, long offset, long length) throws IOException {
        if ((offset >= 0L) && (length >= 0L) && (offset + length <= length())) {
            final SearchableSnapshotIndexInput slice = new SearchableSnapshotIndexInput(sliceDescription, blobContainer, fileInfo, position,
                this.offset + offset, length, NO_SEQUENTIAL_READ_OPTIMIZATION, getBufferSize());
            slice.seek(0L);
            return slice;
        } else {
            throw new IllegalArgumentException("slice() " + sliceDescription + " out of bounds: offset=" + offset
                + ",length=" + length + ",fileLength=" + length() + ": " + this);
        }
    }

    @Override
    public void close() throws IOException {
        closed = true;
        IOUtils.close(streamForSequentialReadsRef.getAndSet(null));
    }

    @Override
    public String toString() {
        return "SearchableSnapshotIndexInput{" +
            "resourceDesc=" + super.toString() +
            ", fileInfo=" + fileInfo +
            ", offset=" + offset +
            ", length=" + length +
            ", position=" + position +
            '}';
    }

    private static class StreamForSequentialReads implements Closeable {
        final InputStream inputStream;
        final int part;
        long pos; // position within this part
        private final long maxPos;

        StreamForSequentialReads(InputStream inputStream, int part, long pos, long streamLength) {
            this.inputStream = Objects.requireNonNull(inputStream);
            this.part = part;
            this.pos = pos;
            this.maxPos = pos + streamLength;
        }

        boolean isFullyRead() {
            assert this.pos <= maxPos;
            return this.pos >= maxPos;
        }

        @Override
        public void close() throws IOException {
            inputStream.close();
        }
    }
}
