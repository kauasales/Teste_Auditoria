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

package org.elasticsearch.index.query;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.index.*;
import org.apache.lucene.queries.TermsFilter;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.ConstantScoreQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.ElasticsearchIllegalArgumentException;
import org.elasticsearch.action.termvector.MultiTermVectorsRequest;
import org.elasticsearch.action.termvector.TermVectorRequest;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.lucene.search.MoreLikeThisQuery;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.index.analysis.Analysis;
import org.elasticsearch.index.mapper.internal.UidFieldMapper;
import org.elasticsearch.index.search.morelikethis.MoreLikeThisFetchService;
import org.elasticsearch.search.internal.SearchContext;

import java.io.IOException;
import java.util.*;

import static org.elasticsearch.index.mapper.Uid.createUidAsBytes;

/**
 *
 */
public class MoreLikeThisQueryParser implements QueryParser {

    public static final String NAME = "mlt";
    private MoreLikeThisFetchService fetchService = null;

    public static class Fields {
        public static final ParseField LIKE_TEXT = new ParseField("like_text");
        public static final ParseField MIN_TERM_FREQ = new ParseField("min_term_freq");
        public static final ParseField MAX_QUERY_TERMS = new ParseField("max_query_terms");
        public static final ParseField MIN_WORD_LENGTH = new ParseField("min_word_length", "min_word_len");
        public static final ParseField MAX_WORD_LENGTH = new ParseField("max_word_length", "max_word_len");
        public static final ParseField MIN_DOC_FREQ = new ParseField("min_doc_freq");
        public static final ParseField MAX_DOC_FREQ = new ParseField("max_doc_freq");
        public static final ParseField BOOST_TERMS = new ParseField("boost_terms");
        public static final ParseField MINIMUM_SHOULD_MATCH = new ParseField("minimum_should_match");
        public static final ParseField PERCENT_TERMS_TO_MATCH = new ParseField("percent_terms_to_match").withAllDeprecated("minimum_should_match");
        public static final ParseField FAIL_ON_UNSUPPORTED_FIELD = new ParseField("fail_on_unsupported_field");
        public static final ParseField STOP_WORDS = new ParseField("stop_words");
        public static final ParseField DOCUMENT_IDS = new ParseField("ids");
        public static final ParseField DOCUMENTS = new ParseField("docs");
        public static final ParseField INCLUDE = new ParseField("include");
        public static final ParseField EXCLUDE = new ParseField("exclude");
    }

    public MoreLikeThisQueryParser() {

    }

    @Inject(optional = true)
    public void setFetchService(@Nullable MoreLikeThisFetchService fetchService) {
        this.fetchService = fetchService;
    }

    @Override
    public String[] names() {
        return new String[]{NAME, "more_like_this", "moreLikeThis"};
    }

    @Override
    public Query parse(QueryParseContext parseContext) throws IOException, QueryParsingException {
        XContentParser parser = parseContext.parser();

        MoreLikeThisQuery mltQuery = new MoreLikeThisQuery();
        mltQuery.setSimilarity(parseContext.searchSimilarity());
        Analyzer analyzer = null;
        List<String> moreLikeFields = null;
        boolean failOnUnsupportedField = true;
        String queryName = null;
        boolean include = false;

        XContentParser.Token token;
        String currentFieldName = null;
        MultiTermVectorsRequest items = new MultiTermVectorsRequest();
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token.isValue()) {
                if (Fields.LIKE_TEXT.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setLikeText(parser.text());
                } else if (Fields.MIN_TERM_FREQ.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMinTermFrequency(parser.intValue());
                } else if (Fields.MAX_QUERY_TERMS.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMaxQueryTerms(parser.intValue());
                } else if (Fields.MIN_DOC_FREQ.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMinDocFreq(parser.intValue());
                } else if (Fields.MAX_DOC_FREQ.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMaxDocFreq(parser.intValue());
                } else if (Fields.MIN_WORD_LENGTH.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMinWordLen(parser.intValue());
                } else if (Fields.MAX_WORD_LENGTH.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMaxWordLen(parser.intValue());
                } else if (Fields.BOOST_TERMS.match(currentFieldName, parseContext.parseFlags())) {
                    float boostFactor = parser.floatValue();
                    if (boostFactor != 0) {
                        mltQuery.setBoostTerms(true);
                        mltQuery.setBoostTermsFactor(boostFactor);
                    }
                } else if (Fields.MINIMUM_SHOULD_MATCH.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMinimumShouldMatch(parser.text());
                } else if (Fields.PERCENT_TERMS_TO_MATCH.match(currentFieldName, parseContext.parseFlags())) {
                    mltQuery.setMinimumShouldMatch(Math.round(parser.floatValue() * 100) + "%");
                } else if ("analyzer".equals(currentFieldName)) {
                    analyzer = parseContext.analysisService().analyzer(parser.text());
                } else if ("boost".equals(currentFieldName)) {
                    mltQuery.setBoost(parser.floatValue());
                } else if (Fields.FAIL_ON_UNSUPPORTED_FIELD.match(currentFieldName, parseContext.parseFlags())) {
                    failOnUnsupportedField = parser.booleanValue();
                } else if ("_name".equals(currentFieldName)) {
                    queryName = parser.text();
                } else if (Fields.INCLUDE.match(currentFieldName, parseContext.parseFlags())) {
                    include = parser.booleanValue();
                } else if (Fields.EXCLUDE.match(currentFieldName, parseContext.parseFlags())) {
                    include = !parser.booleanValue();
                } else {
                    throw new QueryParsingException(parseContext.index(), "[mlt] query does not support [" + currentFieldName + "]");
                }
            } else if (token == XContentParser.Token.START_ARRAY) {
                if (Fields.STOP_WORDS.match(currentFieldName, parseContext.parseFlags())) {
                    Set<String> stopWords = Sets.newHashSet();
                    while ((token = parser.nextToken()) != XContentParser.Token.END_ARRAY) {
                        stopWords.add(parser.text());
                    }
                    mltQuery.setStopWords(stopWords);
                } else if ("fields".equals(currentFieldName)) {
                    moreLikeFields = Lists.newLinkedList();
                    while ((token = parser.nextToken()) != XContentParser.Token.END_ARRAY) {
                        moreLikeFields.add(parser.text());
                    }
                } else if (Fields.DOCUMENT_IDS.match(currentFieldName, parseContext.parseFlags())) {
                    while ((token = parser.nextToken()) != XContentParser.Token.END_ARRAY) {
                        if (!token.isValue()) {
                            throw new ElasticsearchIllegalArgumentException("ids array element should only contain ids");
                        }
                        items.add(newTermVectorRequest().id(parser.text()));
                    }
                } else if (Fields.DOCUMENTS.match(currentFieldName, parseContext.parseFlags())) {
                    while ((token = parser.nextToken()) != XContentParser.Token.END_ARRAY) {
                        if (token != XContentParser.Token.START_OBJECT) {
                            throw new ElasticsearchIllegalArgumentException("docs array element should include an object");
                        }
                        items.add(parseDocuments(parser));
                    }
                } else {
                    throw new QueryParsingException(parseContext.index(), "[mlt] query does not support [" + currentFieldName + "]");
                }
            }
        }

        if (mltQuery.getLikeText() == null && items.isEmpty()) {
            throw new QueryParsingException(parseContext.index(), "more_like_this requires at least 'like_text' or 'ids/docs' to be specified");
        }
        if (moreLikeFields != null && moreLikeFields.isEmpty()) {
            throw new QueryParsingException(parseContext.index(), "more_like_this requires 'fields' to be non-empty");
        }

        // set analyzer
        if (analyzer == null) {
            analyzer = parseContext.mapperService().searchAnalyzer();
        }
        mltQuery.setAnalyzer(analyzer);

        // set like text fields
        boolean useDefaultField = (moreLikeFields == null);
        if (useDefaultField) {
            moreLikeFields = Lists.newArrayList(parseContext.defaultField());
        }
        // possibly remove unsupported fields
        removeUnsupportedFields(moreLikeFields, analyzer, failOnUnsupportedField);
        if (moreLikeFields.isEmpty()) {
            return null;
        }

        List<String> moreLikeThisIndexFields = new ArrayList<>();
        for (String field : moreLikeFields) {
            moreLikeThisIndexFields.add(parseContext.indexName(field));
        }
        mltQuery.setMoreLikeFields(moreLikeThisIndexFields.toArray(new String[moreLikeThisIndexFields.size()]));

        // support for named query
        if (queryName != null) {
            parseContext.addNamedQuery(queryName, mltQuery);
        }

        // handle items
        if (!items.isEmpty()) {
            // set default index, type and fields if not specified
            for (TermVectorRequest item : items) {
                if (item.index() == null) {
                    item.index(parseContext.index().name());
                }
                if (item.type() == null) {
                    if (parseContext.queryTypes().size() > 1) {
                        throw new QueryParsingException(parseContext.index(),
                                "ambiguous type for item with id: " + item.id() + " and index: " + item.index());
                    } else {
                        item.type(parseContext.queryTypes().iterator().next());
                    }
                }
                // default fields if not present but don't override for artificial docs
                if (item.selectedFields() == null && item.doc() == null) {
                    if (useDefaultField) {
                        item.selectedFields("*");
                    } else {
                        item.selectedFields(moreLikeFields.toArray(new String[moreLikeFields.size()]));
                    }
                }
            }
            // fetching the items with multi-termvectors API
            org.apache.lucene.index.Fields[] likeFields = fetchService.fetch(items);
            for (int i = 0; i < likeFields.length; i++) {
                final Map<String, List<String>> fieldToIndexName = new HashMap<>();
                for (String field : likeFields[i]) {
                    String indexName = parseContext.indexName(field);
                    if (indexName.equals(field) == false) {
                        if (fieldToIndexName.containsKey(indexName) == false) {
                            fieldToIndexName.put(indexName, new ArrayList<String>());
                        }
                        fieldToIndexName.get(indexName).add(field);
                    }
                }
                if (fieldToIndexName.isEmpty() == false) {
                    likeFields[i] = new MappedIndexedFields(likeFields[i], fieldToIndexName);
                }
            }
            items.copyContextAndHeadersFrom(SearchContext.current());
            mltQuery.setLikeText(likeFields);

            BooleanQuery boolQuery = new BooleanQuery();
            boolQuery.add(mltQuery, BooleanClause.Occur.SHOULD);
            // exclude the items from the search
            if (!include) {
                handleExclude(boolQuery, items);
            }
            return boolQuery;
        }

        return mltQuery;
    }

    private TermVectorRequest newTermVectorRequest() {
        return new TermVectorRequest()
                .positions(false)
                .offsets(false)
                .payloads(false)
                .fieldStatistics(false)
                .termStatistics(false);
    }

    private TermVectorRequest parseDocuments(XContentParser parser) throws IOException {
        TermVectorRequest termVectorRequest = newTermVectorRequest();
        TermVectorRequest.parseRequest(termVectorRequest, parser);
        return termVectorRequest;
    }

    private List<String> removeUnsupportedFields(List<String> moreLikeFields, Analyzer analyzer, boolean failOnUnsupportedField) throws IOException {
        for (Iterator<String> it = moreLikeFields.iterator(); it.hasNext(); ) {
            final String fieldName = it.next();
            if (!Analysis.generatesCharacterTokenStream(analyzer, fieldName)) {
                if (failOnUnsupportedField) {
                    throw new ElasticsearchIllegalArgumentException("more_like_this doesn't support binary/numeric fields: [" + fieldName + "]");
                } else {
                    it.remove();
                }
            }
        }
        return moreLikeFields;
    }

    private void handleExclude(BooleanQuery boolQuery, MultiTermVectorsRequest likeItems) {
        // artificial docs get assigned a random id and should be disregarded
        List<BytesRef> uids = new ArrayList<>();
        for (TermVectorRequest item : likeItems) {
            if (item.doc() != null) {
                continue;
            }
            uids.add(createUidAsBytes(item.type(), item.id()));
        }
        if (!uids.isEmpty()) {
            TermsFilter filter = new TermsFilter(UidFieldMapper.NAME, uids.toArray(new BytesRef[0]));
            ConstantScoreQuery query = new ConstantScoreQuery(filter);
            boolQuery.add(query, BooleanClause.Occur.MUST_NOT);
        }
    }

    /**
     * This class converts the actual path name to the index name if they happen to be different.
     * This is needed if the "path" : "just_name" feature is used in mappings where paths like `person.name` are indexed
     * into just the leave name of the path ie. in this case `name`. For this case we need to somehow map those names to
     * the actual fields to get the right statistics from the index when we rewrite the MLT query otherwise it will rewrite against
     * the full path name which is not present in the index at all in that case.
     * his will result in an empty query and no results are returned
     */
    private static class MappedIndexedFields extends org.apache.lucene.index.Fields {
        private final Map<String, List<String>> fieldToIndexName;
        private final org.apache.lucene.index.Fields in;

        MappedIndexedFields(org.apache.lucene.index.Fields in, Map<String, List<String>> fieldToIndexName) {
            this.in = in;
            this.fieldToIndexName = Collections.unmodifiableMap(fieldToIndexName);
        }

        @Override
        public Iterator<String> iterator() {
            return fieldToIndexName.keySet().iterator();
        }

        @Override
        public Terms terms(String field) throws IOException {
            List<String> indexNames = fieldToIndexName.get(field);
            if (indexNames == null) {
                return in.terms(field);
            } if (indexNames.size() == 1) {
                return in.terms(indexNames.get(0));
            }else {
                final Terms[] terms = new Terms[indexNames.size()];
                final ReaderSlice[] slice = new ReaderSlice[indexNames.size()];
                for (int i = 0; i < terms.length; i++) {
                    terms[i] = in.terms(indexNames.get(i));
                    slice[i]= new ReaderSlice(0, 1, i);
                }
                return new MultiTerms(terms, slice);
             }
        }

        @Override
        public int size() {
            return fieldToIndexName.size();
        }
    }
}
