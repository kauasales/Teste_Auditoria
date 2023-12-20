/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package org.elasticsearch.index.codec.postings;

import org.apache.lucene.index.Impact;
import org.apache.lucene.index.Impacts;
import org.apache.lucene.store.ByteArrayDataInput;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.util.ArrayUtil;

import java.io.IOException;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.List;
import java.util.RandomAccess;

final class ES812ScoreSkipReader extends ES812SkipReader {

    private final byte[][] impactData;
    private final int[] impactDataLength;
    private final ByteArrayDataInput badi = new ByteArrayDataInput();
    private final Impacts impacts;
    private int numLevels = 1;
    private final MutableImpactList[] perLevelImpacts;

    ES812ScoreSkipReader(IndexInput skipStream, int maxSkipLevels, boolean hasPos, boolean hasOffsets, boolean hasPayloads) {
        super(skipStream, maxSkipLevels, hasPos, hasOffsets, hasPayloads);
        this.impactData = new byte[maxSkipLevels][];
        Arrays.fill(impactData, new byte[0]);
        this.impactDataLength = new int[maxSkipLevels];
        this.perLevelImpacts = new MutableImpactList[maxSkipLevels];
        for (int i = 0; i < perLevelImpacts.length; ++i) {
            perLevelImpacts[i] = new MutableImpactList();
        }
        impacts = new Impacts() {

            @Override
            public int numLevels() {
                return numLevels;
            }

            @Override
            public int getDocIdUpTo(int level) {
                return skipDoc[level];
            }

            @Override
            public List<Impact> getImpacts(int level) {
                assert level < numLevels;
                if (impactDataLength[level] > 0) {
                    badi.reset(impactData[level], 0, impactDataLength[level]);
                    perLevelImpacts[level] = readImpacts(badi, perLevelImpacts[level]);
                    impactDataLength[level] = 0;
                }
                return perLevelImpacts[level];
            }
        };
    }

    @Override
    public int skipTo(int target) throws IOException {
        int result = super.skipTo(target);
        if (numberOfSkipLevels > 0) {
            numLevels = numberOfSkipLevels;
        } else {
            // End of postings don't have skip data anymore, so we fill with dummy data
            // like SlowImpactsEnum.
            numLevels = 1;
            perLevelImpacts[0].length = 1;
            perLevelImpacts[0].impacts[0].freq = Integer.MAX_VALUE;
            perLevelImpacts[0].impacts[0].norm = 1L;
            impactDataLength[0] = 0;
        }
        return result;
    }

    Impacts getImpacts() {
        return impacts;
    }

    @Override
    protected void readImpacts(int level, IndexInput skipStream) throws IOException {
        int length = skipStream.readVInt();
        if (impactData[level].length < length) {
            impactData[level] = new byte[ArrayUtil.oversize(length, Byte.BYTES)];
        }
        skipStream.readBytes(impactData[level], 0, length);
        impactDataLength[level] = length;
    }

    static MutableImpactList readImpacts(ByteArrayDataInput in, MutableImpactList reuse) {
        int maxNumImpacts = in.length(); // at most one impact per byte
        if (reuse.impacts.length < maxNumImpacts) {
            int oldLength = reuse.impacts.length;
            reuse.impacts = ArrayUtil.grow(reuse.impacts, maxNumImpacts);
            for (int i = oldLength; i < reuse.impacts.length; ++i) {
                reuse.impacts[i] = new Impact(Integer.MAX_VALUE, 1L);
            }
        }

        int freq = 0;
        long norm = 0;
        int length = 0;
        while (in.getPosition() < in.length()) {
            int freqDelta = in.readVInt();
            if ((freqDelta & 0x01) != 0) {
                freq += 1 + (freqDelta >>> 1);
                try {
                    norm += 1 + in.readZLong();
                } catch (IOException e) {
                    throw new RuntimeException(e); // cannot happen on a BADI
                }
            } else {
                freq += 1 + (freqDelta >>> 1);
                norm++;
            }
            Impact impact = reuse.impacts[length];
            impact.freq = freq;
            impact.norm = norm;
            length++;
        }
        reuse.length = length;
        return reuse;
    }

    static class MutableImpactList extends AbstractList<Impact> implements RandomAccess {
        int length = 1;
        Impact[] impacts = new Impact[] { new Impact(Integer.MAX_VALUE, 1L) };

        @Override
        public Impact get(int index) {
            return impacts[index];
        }

        @Override
        public int size() {
            return length;
        }
    }
}
