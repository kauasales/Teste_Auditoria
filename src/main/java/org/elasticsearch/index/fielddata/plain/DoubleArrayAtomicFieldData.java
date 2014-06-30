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

package org.elasticsearch.index.fielddata.plain;

import org.apache.lucene.util.FixedBitSet;
import org.apache.lucene.util.RamUsageEstimator;
import org.elasticsearch.common.util.DoubleArray;
import org.elasticsearch.index.fielddata.*;
import org.elasticsearch.index.fielddata.ordinals.Ordinals;

/**
 */
public abstract class DoubleArrayAtomicFieldData extends AbstractAtomicNumericFieldData {

    public static DoubleArrayAtomicFieldData empty() {
        return new Empty();
    }

    protected long size = -1;

    public DoubleArrayAtomicFieldData() {
        super(true);
    }

    @Override
    public void close() {
    }

    static class Empty extends DoubleArrayAtomicFieldData {

        Empty() {
            super();
        }

        @Override
        public LongValues getLongValues() {
            return LongValues.EMPTY;
        }

        @Override
        public DoubleValues getDoubleValues() {
            return DoubleValues.EMPTY;
        }

        @Override
        public long ramBytesUsed() {
            return 0;
        }

        @Override
        public BytesValues getBytesValues() {
            return BytesValues.EMPTY;
        }

        @Override
        public ScriptDocValues getScriptValues() {
            return ScriptDocValues.EMPTY_DOUBLES;
        }
    }

    public static class WithOrdinals extends DoubleArrayAtomicFieldData {

        private final DoubleArray values;
        private final Ordinals ordinals;

        public WithOrdinals(DoubleArray values, Ordinals ordinals) {
            super();
            this.values = values;
            this.ordinals = ordinals;
        }

        @Override
        public long ramBytesUsed() {
            if (size == -1) {
                size = RamUsageEstimator.NUM_BYTES_INT/*size*/ + values.ramBytesUsed() + ordinals.ramBytesUsed();
            }
            return size;
        }


        @Override
        public LongValues getLongValues() {
            return new LongValues(values, ordinals.ordinals());
        }

        @Override
        public DoubleValues getDoubleValues() {
            return new DoubleValues(values, ordinals.ordinals());
        }


        static class LongValues extends org.elasticsearch.index.fielddata.LongValues.WithOrdinals {

            private final DoubleArray values;

            LongValues(DoubleArray values, BytesValues.WithOrdinals ordinals) {
                super(ordinals);
                this.values = values;
            }

            @Override
            public final long getValueByOrd(long ord) {
                assert ord != BytesValues.WithOrdinals.MISSING_ORDINAL;
                return (long) values.get(ord);
            }
        }

        static class DoubleValues extends org.elasticsearch.index.fielddata.DoubleValues.WithOrdinals {

            private final DoubleArray values;

            DoubleValues(DoubleArray values, BytesValues.WithOrdinals ordinals) {
                super(ordinals);
                this.values = values;
            }

            @Override
            public double getValueByOrd(long ord) {
                assert ord != BytesValues.WithOrdinals.MISSING_ORDINAL;
                return values.get(ord);
            }
        }
    }

    /**
     * A single valued case, where not all values are "set", so we have a FixedBitSet that
     * indicates which values have an actual value.
     */
    public static class SingleFixedSet extends DoubleArrayAtomicFieldData {

        private final DoubleArray values;
        private final FixedBitSet set;

        public SingleFixedSet(DoubleArray values, FixedBitSet set) {
            super();
            this.values = values;
            this.set = set;
        }

        @Override
        public long ramBytesUsed() {
            if (size == -1) {
                size = RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + values.ramBytesUsed() + RamUsageEstimator.sizeOf(set.getBits());
            }
            return size;
        }

        @Override
        public LongValues getLongValues() {
            return new LongValues(values, set);
        }

        @Override
        public DoubleValues getDoubleValues() {
            return new DoubleValues(values, set);
        }

        static class LongValues extends org.elasticsearch.index.fielddata.LongValues {

            private final DoubleArray values;
            private final FixedBitSet set;

            LongValues(DoubleArray values, FixedBitSet set) {
                super(false);
                this.values = values;
                this.set = set;
            }

            @Override
            public int setDocument(int docId) {
                this.docId = docId;
                return  set.get(docId) ? 1 : 0;
            }

            @Override
            public long nextValue() {
                return (long) values.get(docId);
            }
            }

        static class DoubleValues extends org.elasticsearch.index.fielddata.DoubleValues {

            private final DoubleArray values;
            private final FixedBitSet set;

            DoubleValues(DoubleArray values, FixedBitSet set) {
                super(false);
                this.values = values;
                this.set = set;
            }

            @Override
            public int setDocument(int docId) {
                this.docId = docId;
                return set.get(docId) ? 1 : 0;
            }

            @Override
            public double nextValue() {
                return values.get(docId);
            }
        }
    }

    /**
     * Assumes all the values are "set", and docId is used as the index to the value array.
     */
    public static class Single extends DoubleArrayAtomicFieldData {

        private final DoubleArray values;

        /**
         * Note, here, we assume that there is no offset by 1 from docId, so position 0
         * is the value for docId 0.
         */
        public Single(DoubleArray values) {
            super();
            this.values = values;
        }

        @Override
        public long ramBytesUsed() {
            if (size == -1) {
                size = RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + values.ramBytesUsed();
            }
            return size;
        }

        @Override
        public LongValues getLongValues() {
            return new LongValues(values);
        }

        @Override
        public DoubleValues getDoubleValues() {
            return new DoubleValues(values);
        }

        static final class LongValues extends DenseLongValues {

            private final DoubleArray values;

            LongValues(DoubleArray values) {
                super(false);
                this.values = values;
            }

            @Override
            public long nextValue() {
                return (long) values.get(docId);
            }
        }

        static final class DoubleValues extends DenseDoubleValues {

            private final DoubleArray values;

            DoubleValues(DoubleArray values) {
                super(false);
                this.values = values;
            }

            @Override
            public double nextValue() {
                return values.get(docId);
            }
            
        }
    }
}
