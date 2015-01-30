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
package org.elasticsearch.action.termvectors;

import com.google.common.util.concurrent.AtomicLongMap;
import org.apache.lucene.index.*;
import org.apache.lucene.search.TermStatistics;
import org.apache.lucene.search.similarities.DefaultSimilarity;
import org.apache.lucene.search.similarities.TFIDFSimilarity;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.search.dfs.AggregatedDfs;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class TermVectorsFilter {
    public static final int DEFAULT_MAX_QUERY_TERMS = 25;
    public static final int DEFAULT_MIN_TERM_FREQ = 0;
    public static final int DEFAULT_MAX_TERM_FREQ = Integer.MAX_VALUE;
    public static final int DEFAULT_MIN_DOC_FREQ = 0;
    public static final int DEFAULT_MAX_DOC_FREQ = Integer.MAX_VALUE;
    public static final int DEFAULT_MIN_WORD_LENGTH = 0;
    public static final int DEFAULT_MAX_WORD_LENGTH = 0;

    private int maxNumTerms = DEFAULT_MAX_QUERY_TERMS;
    private int minTermFreq = DEFAULT_MIN_TERM_FREQ;
    private int maxTermFreq = DEFAULT_MAX_TERM_FREQ;
    private int minDocFreq = DEFAULT_MIN_DOC_FREQ;
    private int maxDocFreq = DEFAULT_MAX_DOC_FREQ;
    private int minWordLength = DEFAULT_MIN_WORD_LENGTH;
    private int maxWordLength = DEFAULT_MAX_WORD_LENGTH;

    private Fields fields;
    private Fields topLevelFields;
    private final Set<String> selectedFields;
    private AggregatedDfs dfs;
    private Map<Term, ScoreTerm> scoreTerms;
    private AtomicLongMap<String> sizes;
    private TFIDFSimilarity similarity;

    public TermVectorsFilter(Fields termVectorsByField, Fields topLevelFields, Set<String> selectedFields, @Nullable AggregatedDfs dfs) {
        this.fields = termVectorsByField;
        this.topLevelFields = topLevelFields;
        this.selectedFields = selectedFields;

        this.dfs = dfs;
        this.scoreTerms = new HashMap<>();
        this.sizes = AtomicLongMap.create();
        this.similarity = new DefaultSimilarity();
    }

    public void setSettings(TermVectorsRequest.FilterSettings settings) {
        if (settings.maxNumTerms != null) {
            setMaxNumTerms(settings.maxNumTerms);
        }
        if (settings.minTermFreq != null) {
            setMinTermFreq(settings.minTermFreq);
        }
        if (settings.maxTermFreq != null) {
            setMaxTermFreq(settings.maxTermFreq);
        }
        if (settings.minDocFreq != null) {
            setMinDocFreq(settings.minDocFreq);
        }
        if (settings.maxDocFreq != null) {
            setMaxDocFreq(settings.maxDocFreq);
        }
        if (settings.minWordLength != null) {
            setMinWordLength(settings.minWordLength);
        }
        if (settings.maxWordLength != null) {
            setMaxWordLength(settings.maxWordLength);
        }
    }

    public ScoreTerm getScoreTerm(Term term) {
        return scoreTerms.get(term);
    }

    public boolean hasScoreTerm(Term term) {
        return getScoreTerm(term) != null;
    }

    public long size(String fieldName) {
        return sizes.get(fieldName);
    }

    public int getMaxNumTerms() {
        return maxNumTerms;
    }

    public int getMinTermFreq() {
        return minTermFreq;
    }

    public int getMaxTermFreq() {
        return maxTermFreq;
    }

    public int getMinDocFreq() {
        return minDocFreq;
    }

    public int getMaxDocFreq() {
        return maxDocFreq;
    }

    public int getMinWordLength() {
        return minWordLength;
    }

    public int getMaxWordLength() {
        return maxWordLength;
    }

    public void setMaxNumTerms(int maxNumTerms) {
        this.maxNumTerms = maxNumTerms;
    }

    public void setMinTermFreq(int minTermFreq) {
        this.minTermFreq = minTermFreq;
    }

    public void setMaxTermFreq(int maxTermFreq) {
        this.maxTermFreq = maxTermFreq;
    }

    public void setMinDocFreq(int minDocFreq) {
        this.minDocFreq = minDocFreq;
    }

    public void setMaxDocFreq(int maxDocFreq) {
        this.maxDocFreq = maxDocFreq;
    }

    public void setMinWordLength(int minWordLength) {
        this.minWordLength = minWordLength;
    }

    public void setMaxWordLength(int maxWordLength) {
        this.maxWordLength = maxWordLength;
    }

    public static final class ScoreTerm {
        public String field;
        public String word;
        public float score;

        ScoreTerm(String field, String word, float score) {
            this.field = field;
            this.word = word;
            this.score = score;
        }

        void update(String field, String word, float score) {
            this.field = field;
            this.word = word;
            this.score = score;
        }
    }

    public void selectBestTerms() throws IOException {
        TermsEnum termsEnum = null;
        DocsEnum docsEnum = null;
        TermsEnum topLevelTermsEnum = null;

        for (String fieldName : fields) {
            if ((selectedFields != null) && (!selectedFields.contains(fieldName))) {
                continue;
            }

            Terms terms = fields.terms(fieldName);
            Terms topLevelTerms = topLevelFields.terms(fieldName);

            // if no terms found, take the retrieved term vector fields for stats
            if (topLevelTerms == null) {
                topLevelTerms = terms;
            }

            long numDocs = getDocCount(fieldName, topLevelTerms);

            // one queue per field name
            ScoreTermsQueue queue = new ScoreTermsQueue(Math.min(maxNumTerms, (int) terms.size()));

            // select terms with highest tf-idf
            termsEnum = terms.iterator(termsEnum);
            topLevelTermsEnum = topLevelTerms.iterator(topLevelTermsEnum);
            while (termsEnum.next() != null) {
                BytesRef termBytesRef = termsEnum.term();
                topLevelTermsEnum.seekExact(termBytesRef);
                Term term = new Term(fieldName, termBytesRef);

                TermStatistics termStats = getTermStatistics(topLevelTermsEnum, term);
                int freq = getTermFreq(termsEnum, docsEnum);

                // filter terms based on stats first
                if (!isAccepted(freq, termStats.docFreq(), term.bytes().utf8ToString())) {
                    continue;
                }

                // then based on a score
                float score = computeScore(termStats, freq, numDocs);
                queue.addOrUpdate(new ScoreTerm(term.field(), term.bytes().utf8ToString(), score));
            }

            // retain the best terms for quick lookups
            ScoreTerm scoreTerm;
            while ((scoreTerm = queue.pop()) != null) {
                scoreTerms.put(new Term(scoreTerm.field, scoreTerm.word), scoreTerm);
                sizes.incrementAndGet(scoreTerm.field);
            }
        }
    }

    private boolean isAccepted(int freq, long docFreq, String word) {
        // filter out words that don't occur enough times in the source
        if (minTermFreq > 0 && freq < minTermFreq) {
            return false;
        }
        // filter out words that occur in the source
        if (freq > maxTermFreq) {
            return false;
        }
        // filter out words that don't occur in enough docs
        if (minDocFreq > 0 && docFreq < minDocFreq) {
            return false;
        }
        // filter out words that occur in too many docs
        if (docFreq > maxDocFreq) {
            return false;
        }
        // index update problem?
        if (docFreq == 0) {
            return false;
        }
        // filter out words based on length
        int len = word.length();
        if (minWordLength > 0 && len < minWordLength) {
            return false;
        }
        if (maxWordLength > 0 && len > maxWordLength) {
            return false;
        }
        return true;
    }

    private long getDocCount(String fieldName, Terms topLevelTerms) throws IOException {
        if (dfs != null) {
            return dfs.fieldStatistics().get(fieldName).docCount();
        }
        return topLevelTerms.getDocCount();
    }

    private TermStatistics getTermStatistics(TermsEnum termsEnum, Term term) throws IOException {
        if (dfs != null) {
            return dfs.termStatistics().get(term);
        }
        return new TermStatistics(termsEnum.term(), termsEnum.docFreq(), termsEnum.totalTermFreq());
    }

    private int getTermFreq(TermsEnum termsEnum, DocsEnum docsEnum) throws IOException {
        docsEnum = termsEnum.docs(null, docsEnum);
        docsEnum.nextDoc();
        return docsEnum.freq();
    }

    private float computeScore(TermStatistics termStats, int freq, long numDocs) {
        return freq * similarity.idf(termStats.docFreq(), numDocs);
    }

    private static class ScoreTermsQueue extends org.apache.lucene.util.PriorityQueue<ScoreTerm> {
        private final int limit;

        ScoreTermsQueue(int maxSize) {
            super(maxSize);
            this.limit = maxSize;
        }

        @Override
        protected boolean lessThan(ScoreTerm a, ScoreTerm b) {
            return a.score < b.score;
        }

        public void addOrUpdate(ScoreTerm scoreTerm) {
            if (this.size() < limit) {
                // there is still space in the queue
                this.add(scoreTerm);
            } else {
                // otherwise update the smallest in the queue in place and update the queue
                ScoreTerm scoreTermTop = this.top();
                if (scoreTermTop.score < scoreTerm.score) {
                    scoreTermTop.update(scoreTerm.field, scoreTerm.word, scoreTerm.score);
                    this.updateTop();
                }
            }
        }
    }
}
