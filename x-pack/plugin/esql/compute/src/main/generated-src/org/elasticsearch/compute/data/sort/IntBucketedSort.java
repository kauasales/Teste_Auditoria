/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.compute.data.sort;

import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.BitArray;
import org.elasticsearch.common.util.IntArray;
import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.BlockFactory;
import org.elasticsearch.compute.data.IntVector;
import org.elasticsearch.core.Releasable;
import org.elasticsearch.core.Releasables;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.search.sort.BucketedSort;
import org.elasticsearch.search.sort.SortOrder;

import java.util.Arrays;

/**
 * Aggregates the top N int values per bucket.
 * See {@link BucketedSort} for more information.
 * This class is generated. Edit @{code X-BucketedSort.java.st} instead of this file.
 */
public class IntBucketedSort implements Releasable {

    private final BigArrays bigArrays;
    private final SortOrder order;
    private final int bucketSize;
    /**
     * {@code true} if the bucket is in heap mode, {@code false} if
     * it is still gathering.
     */
    private final BitArray heapMode;
    private IntArray values;

    public IntBucketedSort(BigArrays bigArrays, SortOrder order, int bucketSize) {
        this.bigArrays = bigArrays;
        this.order = order;
        this.bucketSize = bucketSize;
        heapMode = new BitArray(0, bigArrays);

        boolean success = false;
        try {
            values = bigArrays.newIntArray(0, false);
            success = true;
        } finally {
            if (success == false) {
                close();
            }
        }
    }

    /**
     * The order of the sort.
     */
    public SortOrder getOrder() {
        return order;
    }

    /**
     * The number of values to store per bucket.
     */
    public int getBucketSize() {
        return bucketSize;
    }

    /**
     * Get the bound indexes (inclusive, exclusive) of the values for a bucket.
     * Returns [0, 0] if the bucket has never been collected.
     */
    private Tuple<Long, Long> getBucketValuesBounds(long bucket) {
        long rootIndex = bucket * bucketSize;
        if (rootIndex >= values.size()) {
            // We've never seen this bucket.
            return Tuple.tuple(0L, 0L);
        }
        long start = inHeapMode(bucket) ? rootIndex : (rootIndex + getNextGatherOffset(rootIndex) + 1);
        long end = rootIndex + bucketSize;
        return Tuple.tuple(start, end);
    }

    /**
     * Merge the values from {@code other}'s {@code otherGroupId} into {@code groupId}.
     */
    public void merge(int groupId, IntBucketedSort other, int otherGroupId) {
        var otherBounds = other.getBucketValuesBounds(otherGroupId);

        // TODO: This can be improved for heapified buckets by making use of the heap structures
        for (long i = otherBounds.v1(); i < otherBounds.v2(); i++) {
            collect(other.values.get(i), groupId);
        }
    }

    /**
     * Creates a block with the values from the {@code selected} groups.
     */
    public Block toBlock(BlockFactory blockFactory, IntVector selected) {
        // Used to sort the values in the bucket.
        var bucketValues = new int[bucketSize];

        try (var builder = blockFactory.newIntBlockBuilder(selected.getPositionCount())) {
            for (int s = 0; s < selected.getPositionCount(); s++) {
                int bucket = selected.getInt(s);

                var bounds = getBucketValuesBounds(bucket);
                var size = bounds.v2() - bounds.v1();

                if (size == 0) {
                    builder.appendNull();
                    continue;
                }

                if (size == 1) {
                    builder.appendInt(values.get(bounds.v1()));
                    continue;
                }

                for (int i = 0; i < size; i++) {
                    bucketValues[i] = values.get(bounds.v1() + i);
                }

                Arrays.sort(bucketValues, 0, (int) size);

                builder.beginPositionEntry();
                if (order == SortOrder.ASC) {
                    for (int i = 0; i < size; i++) {
                        builder.appendInt(bucketValues[i]);
                    }
                } else {
                    for (int i = (int) size - 1; i >= 0; i--) {
                        builder.appendInt(bucketValues[i]);
                    }
                }
                builder.endPositionEntry();
            }
            return builder.build();
        }
    }

    /**
     * Is this bucket a min heap {@code true} or in gathering mode {@code false}?
     */
    private boolean inHeapMode(long bucket) {
        return heapMode.get(bucket);
    }

    /**
     * Get the next index that should be "gathered" for a bucket rooted
     * at {@code rootIndex}.
     */
    private int getNextGatherOffset(long rootIndex) {
        return values.get(rootIndex);
    }

    /**
     * Set the next index that should be "gathered" for a bucket rooted
     * at {@code rootIndex}.
     */
    private void setNextGatherOffset(long rootIndex, int offset) {
        values.set(rootIndex, offset);
    }

    /**
     * {@code true} if the entry at index {@code lhs} is "better" than
     * the entry at {@code rhs}. "Better" in this means "lower" for
     * {@link SortOrder#ASC} and "higher" for {@link SortOrder#DESC}.
     */
    private boolean betterThan(int lhs, int rhs) {
        return getOrder().reverseMul() * Integer.compare(lhs, rhs) < 0;
    }

    /**
     * Swap the data at two indices.
     */
    private void swap(long lhs, long rhs) {
        var tmp = values.get(lhs);
        values.set(lhs, values.get(rhs));
        values.set(rhs, tmp);
    }

    /**
     * Allocate storage for more buckets and store the "next gather offset"
     * for those new buckets.
     */
    private void grow(long minSize) {
        long oldMax = values.size();
        values = bigArrays.grow(values, minSize);
        // Set the next gather offsets for all newly allocated buckets.
        setNextGatherOffsets(oldMax - (oldMax % getBucketSize()));
    }

    /**
     * Maintain the "next gather offsets" for newly allocated buckets.
     */
    private void setNextGatherOffsets(long startingAt) {
        int nextOffset = getBucketSize() - 1;
        for (long bucketRoot = startingAt; bucketRoot < values.size(); bucketRoot += getBucketSize()) {
            setNextGatherOffset(bucketRoot, nextOffset);
        }
    }

    /**
     * Heapify a bucket whose entries are in random order.
     * <p>
     * This works by validating the heap property on each node, iterating
     * "upwards", pushing any out of order parents "down". Check out the
     * <a href="https://en.wikipedia.org/w/index.php?title=Binary_heap&oldid=940542991#Building_a_heap">wikipedia</a>
     * entry on binary heaps for more about this.
     * </p>
     * <p>
     * While this *looks* like it could easily be {@code O(n * log n)}, it is
     * a fairly well studied algorithm attributed to Floyd. There's
     * been a bunch of work that puts this at {@code O(n)}, close to 1.88n worst
     * case.
     * </p>
     * <ul>
     * <li>Hayward, Ryan; McDiarmid, Colin (1991).
     * <a href="https://web.archive.org/web/20160205023201/http://www.stats.ox.ac.uk/__data/assets/pdf_file/0015/4173/heapbuildjalg.pdf">
     * Average Case Analysis of Heap Building byRepeated Insertion</a> J. Algorithms.
     * <li>D.E. Knuth, ”The Art of Computer Programming, Vol. 3, Sorting and Searching”</li>
     * </ul>
     * @param rootIndex the index the start of the bucket
     */
    private void heapify(long rootIndex) {
        int maxParent = bucketSize / 2 - 1;
        for (int parent = maxParent; parent >= 0; parent--) {
            downHeap(rootIndex, parent);
        }
    }

    /**
     * Correct the heap invariant of a parent and its children. This
     * runs in {@code O(log n)} time.
     * @param rootIndex index of the start of the bucket
     * @param parent Index within the bucket of the parent to check.
     *               For example, 0 is the "root".
     */
    private void downHeap(long rootIndex, int parent) {
        while (true) {
            long parentIndex = rootIndex + parent;
            int worst = parent;
            long worstIndex = parentIndex;
            int leftChild = parent * 2 + 1;
            long leftIndex = rootIndex + leftChild;
            if (leftChild < bucketSize) {
                if (betterThan(values.get(worstIndex), values.get(leftIndex))) {
                    worst = leftChild;
                    worstIndex = leftIndex;
                }
                int rightChild = leftChild + 1;
                long rightIndex = rootIndex + rightChild;
                if (rightChild < bucketSize && betterThan(values.get(worstIndex), values.get(rightIndex))) {
                    worst = rightChild;
                    worstIndex = rightIndex;
                }
            }
            if (worst == parent) {
                break;
            }
            swap(worstIndex, parentIndex);
            parent = worst;
        }
    }

    @Override
    public final void close() {
        Releasables.close(values, heapMode);
    }

    /**
     * Collects a value stored in the array[0] position.
     * <p>
     *     It may or may not be inserted in the heap, depending on if it is better than the current root.
     * </p>
     */
    public void collect(int value, long bucket) {
        long rootIndex = bucket * bucketSize;
        if (inHeapMode(bucket)) {
            if (betterThan(value, values.get(rootIndex))) {
                values.set(rootIndex, value);
                downHeap(rootIndex, 0);
            }
            return;
        }
        // Gathering mode
        long requiredSize = rootIndex + bucketSize;
        if (values.size() < requiredSize) {
            grow(requiredSize);
        }
        int next = getNextGatherOffset(rootIndex);
        assert 0 <= next && next < bucketSize
            : "Expected next to be in the range of valid buckets [0 <= " + next + " < " + bucketSize + "]";
        long index = next + rootIndex;
        values.set(index, value);
        if (next == 0) {
            heapMode.set(bucket);
            heapify(rootIndex);
        } else {
            setNextGatherOffset(rootIndex, next - 1);
        }
    }
}
