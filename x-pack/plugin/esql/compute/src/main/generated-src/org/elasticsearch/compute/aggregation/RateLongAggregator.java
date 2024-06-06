/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.compute.aggregation;

import org.apache.lucene.util.Accountable;
import org.apache.lucene.util.RamUsageEstimator;
import org.elasticsearch.common.breaker.CircuitBreaker;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.ObjectArray;
import org.elasticsearch.compute.ann.GroupingAggregator;
import org.elasticsearch.compute.ann.IntermediateState;
import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.BlockFactory;
import org.elasticsearch.compute.data.DoubleBlock;
import org.elasticsearch.compute.data.DoubleVector;
import org.elasticsearch.compute.data.IntVector;
import org.elasticsearch.compute.data.LongBlock;
import org.elasticsearch.compute.operator.DriverContext;
import org.elasticsearch.core.Releasable;
import org.elasticsearch.core.Releasables;

import java.util.Arrays;

/**
 * A rate grouping aggregation definition for long.
 * This class is generated. Edit `X-RateAggregator.java.st` instead.
 */
@GroupingAggregator(
    includeTimestamps = true,
    value = {
        @IntermediateState(name = "timestamps", type = "LONG_BLOCK"),
        @IntermediateState(name = "values", type = "LONG_BLOCK"),
        @IntermediateState(name = "resets", type = "DOUBLE") }
)
public class RateLongAggregator {

    public static LongRateGroupingState initGrouping(DriverContext driverContext, long unitInMillis) {
        return new LongRateGroupingState(driverContext.bigArrays(), driverContext.breaker(), unitInMillis);
    }

    public static void combine(LongRateGroupingState current, int groupId, long timestamp, long value) {
        current.append(groupId, timestamp, value);
    }

    public static void combineIntermediate(
        LongRateGroupingState current,
        int groupId,
        LongBlock timestamps,
        LongBlock values,
        double reset,
        int otherPosition
    ) {
        current.combine(groupId, timestamps, values, reset, otherPosition);
    }

    public static void combineStates(
        LongRateGroupingState current,
        int currentGroupId, // make the stylecheck happy
        LongRateGroupingState otherState,
        int otherGroupId
    ) {
        current.combineState(currentGroupId, otherState, otherGroupId);
    }

    public static Block evaluateFinal(LongRateGroupingState state, IntVector selected, DriverContext driverContext) {
        return state.evaluateFinal(selected, driverContext.blockFactory());
    }

    private static class LongRateState {
        static final long BASE_RAM_USAGE = RamUsageEstimator.sizeOfObject(LongRateState.class);
        final long[] timestamps; // descending order
        final long[] values;
        double reset = 0;

        LongRateState(int initialSize) {
            this.timestamps = new long[initialSize];
            this.values = new long[initialSize];
        }

        LongRateState(long[] ts, long[] vs) {
            this.timestamps = ts;
            this.values = vs;
        }

        private long dv(long v0, long v1) {
            // counter reset detection
            return v0 > v1 ? v1 : v1 - v0;
        }

        void append(long t, long v) {
            assert timestamps.length == 2 : "expected two timestamps; got " + timestamps.length;
            assert t < timestamps[1] : "@timestamp goes backward: " + t + " >= " + timestamps[1];
            reset += dv(v, values[1]) + dv(values[1], values[0]) - dv(v, values[0]);
            timestamps[1] = t;
            values[1] = v;
        }

        int entries() {
            return timestamps.length;
        }

        static long bytesUsed(int entries) {
            var ts = RamUsageEstimator.alignObjectSize(RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + (long) Long.BYTES * entries);
            var vs = RamUsageEstimator.alignObjectSize(RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + (long) Long.BYTES * entries);
            return BASE_RAM_USAGE + ts + vs;
        }
    }

    public static final class LongRateGroupingState implements Releasable, Accountable, GroupingAggregatorState {
        private ObjectArray<LongRateState> states;
        private final long unitInMillis;
        private final BigArrays bigArrays;
        private final CircuitBreaker breaker;
        private long stateBytes; // for individual states

        LongRateGroupingState(BigArrays bigArrays, CircuitBreaker breaker, long unitInMillis) {
            this.bigArrays = bigArrays;
            this.breaker = breaker;
            this.states = bigArrays.newObjectArray(1);
            this.unitInMillis = unitInMillis;
        }

        void ensureCapacity(int groupId) {
            states = bigArrays.grow(states, groupId + 1);
        }

        void adjustBreaker(long bytes) {
            breaker.addEstimateBytesAndMaybeBreak(bytes, "<<rate aggregation>>");
            stateBytes += bytes;
            assert stateBytes >= 0 : stateBytes;
        }

        void append(int groupId, long timestamp, long value) {
            ensureCapacity(groupId);
            var state = states.get(groupId);
            if (state == null) {
                adjustBreaker(LongRateState.bytesUsed(1));
                state = new LongRateState(new long[] { timestamp }, new long[] { value });
                states.set(groupId, state);
            } else {
                if (state.entries() == 1) {
                    adjustBreaker(LongRateState.bytesUsed(2));
                    state = new LongRateState(new long[] { state.timestamps[0], timestamp }, new long[] { state.values[0], value });
                    states.set(groupId, state);
                    adjustBreaker(-LongRateState.bytesUsed(1)); // old state
                } else {
                    state.append(timestamp, value);
                }
            }
        }

        void combine(int groupId, LongBlock timestamps, LongBlock values, double reset, int otherPosition) {
            final int valueCount = timestamps.getValueCount(otherPosition);
            if (valueCount == 0) {
                return;
            }
            final int firstIndex = timestamps.getFirstValueIndex(otherPosition);
            ensureCapacity(groupId);
            var state = states.get(groupId);
            if (state == null) {
                adjustBreaker(LongRateState.bytesUsed(valueCount));
                state = new LongRateState(valueCount);
                state.reset = reset;
                states.set(groupId, state);
                // TODO: add bulk_copy to Block
                for (int i = 0; i < valueCount; i++) {
                    state.timestamps[i] = timestamps.getLong(firstIndex + i);
                    state.values[i] = values.getLong(firstIndex + i);
                }
            } else {
                adjustBreaker(LongRateState.bytesUsed(state.entries() + valueCount));
                var newState = new LongRateState(state.entries() + valueCount);
                newState.reset = state.reset + reset;
                states.set(groupId, newState);
                merge(state, newState, firstIndex, valueCount, timestamps, values);
                adjustBreaker(-LongRateState.bytesUsed(state.entries())); // old state
            }
        }

        void merge(LongRateState curr, LongRateState dst, int firstIndex, int rightCount, LongBlock timestamps, LongBlock values) {
            int i = 0, j = 0, k = 0;
            final int leftCount = curr.entries();
            while (i < leftCount && j < rightCount) {
                final var t1 = curr.timestamps[i];
                final var t2 = timestamps.getLong(firstIndex + j);
                if (t1 > t2) {
                    dst.timestamps[k] = t1;
                    dst.values[k] = curr.values[i];
                    ++i;
                } else {
                    dst.timestamps[k] = t2;
                    dst.values[k] = values.getLong(firstIndex + j);
                    ++j;
                }
                ++k;
            }
            if (i < leftCount) {
                System.arraycopy(curr.timestamps, i, dst.timestamps, k, leftCount - i);
                System.arraycopy(curr.values, i, dst.values, k, leftCount - i);
            }
            while (j < rightCount) {
                dst.timestamps[k] = timestamps.getLong(firstIndex + j);
                dst.values[k] = values.getLong(firstIndex + j);
                ++k;
                ++j;
            }
        }

        void combineState(int groupId, LongRateGroupingState otherState, int otherGroupId) {
            var other = otherGroupId < otherState.states.size() ? otherState.states.get(otherGroupId) : null;
            if (other == null) {
                return;
            }
            ensureCapacity(groupId);
            var curr = states.get(groupId);
            if (curr == null) {
                var len = other.entries();
                adjustBreaker(LongRateState.bytesUsed(len));
                curr = new LongRateState(Arrays.copyOf(other.timestamps, len), Arrays.copyOf(other.values, len));
                curr.reset = other.reset;
                states.set(groupId, curr);
            } else {
                states.set(groupId, mergeState(curr, other));
            }
        }

        LongRateState mergeState(LongRateState s1, LongRateState s2) {
            var newLen = s1.entries() + s2.entries();
            adjustBreaker(LongRateState.bytesUsed(newLen));
            var dst = new LongRateState(newLen);
            dst.reset = s1.reset + s2.reset;
            int i = 0, j = 0, k = 0;
            while (i < s1.entries() && j < s2.entries()) {
                if (s1.timestamps[i] > s2.timestamps[j]) {
                    dst.timestamps[k] = s1.timestamps[i];
                    dst.values[k] = s1.values[i];
                    ++i;
                } else {
                    dst.timestamps[k] = s2.timestamps[j];
                    dst.values[k] = s2.values[j];
                    ++j;
                }
                ++k;
            }
            System.arraycopy(s1.timestamps, i, dst.timestamps, k, s1.entries() - i);
            System.arraycopy(s1.values, i, dst.values, k, s1.entries() - i);
            System.arraycopy(s2.timestamps, j, dst.timestamps, k, s2.entries() - j);
            System.arraycopy(s2.values, j, dst.values, k, s2.entries() - j);
            return dst;
        }

        @Override
        public long ramBytesUsed() {
            return states.ramBytesUsed() + stateBytes;
        }

        @Override
        public void close() {
            Releasables.close(states, () -> adjustBreaker(-stateBytes));
        }

        @Override
        public void toIntermediate(Block[] blocks, int offset, IntVector selected, DriverContext driverContext) {
            assert blocks.length >= offset + 3 : "blocks=" + blocks.length + ",offset=" + offset;
            final BlockFactory blockFactory = driverContext.blockFactory();
            final int positionCount = selected.getPositionCount();
            try (
                LongBlock.Builder timestamps = blockFactory.newLongBlockBuilder(positionCount * 2);
                LongBlock.Builder values = blockFactory.newLongBlockBuilder(positionCount * 2);
                DoubleVector.FixedBuilder resets = blockFactory.newDoubleVectorFixedBuilder(positionCount)
            ) {
                for (int i = 0; i < positionCount; i++) {
                    final var groupId = selected.getInt(i);
                    final var state = groupId < states.size() ? states.get(groupId) : null;
                    if (state != null) {
                        timestamps.beginPositionEntry();
                        for (long t : state.timestamps) {
                            timestamps.appendLong(t);
                        }
                        timestamps.endPositionEntry();

                        values.beginPositionEntry();
                        for (long v : state.values) {
                            values.appendLong(v);
                        }
                        values.endPositionEntry();

                        resets.appendDouble(state.reset, i);
                    } else {
                        timestamps.appendNull();
                        values.appendNull();
                        resets.appendDouble(0, i);
                    }
                }
                blocks[offset] = timestamps.build();
                blocks[offset + 1] = values.build();
                blocks[offset + 2] = resets.build().asBlock();
            }
        }

        Block evaluateFinal(IntVector selected, BlockFactory blockFactory) {
            int positionCount = selected.getPositionCount();
            try (DoubleBlock.Builder rates = blockFactory.newDoubleBlockBuilder(positionCount)) {
                for (int p = 0; p < positionCount; p++) {
                    final var groupId = selected.getInt(p);
                    final var state = groupId < states.size() ? states.get(groupId) : null;
                    if (state == null) {
                        rates.appendNull();
                        continue;
                    }
                    int len = state.entries();
                    long dt = state.timestamps[0] - state.timestamps[len - 1];
                    if (dt == 0) {
                        // TODO: maybe issue warning when we don't have enough sample?
                        rates.appendNull();
                    } else {
                        double reset = state.reset;
                        for (int i = 1; i < len; i++) {
                            if (state.values[i - 1] < state.values[i]) {
                                reset += state.values[i];
                            }
                        }
                        double dv = state.values[0] - state.values[len - 1] + reset;
                        rates.appendDouble(dv * unitInMillis / dt);
                    }
                }
                return rates.build();
            }
        }

        void enableGroupIdTracking(SeenGroupIds seenGroupIds) {
            // noop - we handle the null states inside `toIntermediate` and `evaluateFinal`
        }
    }
}
