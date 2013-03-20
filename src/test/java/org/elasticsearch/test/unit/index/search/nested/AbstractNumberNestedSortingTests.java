/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.test.unit.index.search.nested;

import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.*;
import org.apache.lucene.search.join.ScoreMode;
import org.apache.lucene.search.join.ToParentBlockJoinQuery;
import org.elasticsearch.common.lucene.search.AndFilter;
import org.elasticsearch.common.lucene.search.NotFilter;
import org.elasticsearch.common.lucene.search.TermFilter;
import org.elasticsearch.common.lucene.search.XFilteredQuery;
import org.elasticsearch.index.fielddata.IndexFieldData;
import org.elasticsearch.index.fielddata.fieldcomparator.SortMode;
import org.elasticsearch.index.search.nested.NestedFieldComparatorSource;
import org.elasticsearch.test.unit.index.fielddata.AbstractFieldDataTests;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

/**
 */
public abstract class AbstractNumberNestedSortingTests extends AbstractFieldDataTests {

    @Test
    public void testNestedSorting() throws Exception {
        List<Document> docs = new ArrayList<Document>();
        Document document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 1, Field.Store.NO));
        docs.add(document);
        writer.addDocuments(docs);
        writer.commit();

        docs.clear();
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 2, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 2, Field.Store.NO));
        docs.add(document);
        writer.addDocuments(docs);

        docs.clear();
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 1, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 3, Field.Store.NO));
        docs.add(document);
        writer.addDocuments(docs);

        docs.clear();
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "F", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 4, Field.Store.NO));
        document.add(new StringField("filter_1", "F", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 4, Field.Store.NO));
        docs.add(document);
        writer.addDocuments(docs);
        writer.commit();

        docs.clear();
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "F", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "F", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 5, Field.Store.NO));
        document.add(new StringField("filter_1", "F", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 5, Field.Store.NO));
        docs.add(document);
        writer.addDocuments(docs);

        docs.clear();
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 6, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 6, Field.Store.NO));
        docs.add(document);
        writer.addDocuments(docs);

        // This doc will not be included, because it doesn't have nested docs
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 7, Field.Store.NO));
        writer.addDocument(document);

        docs.clear();
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "T", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 3, Field.Store.NO));
        document.add(new StringField("filter_1", "F", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(createField("field2", 7, Field.Store.NO));
        document.add(new StringField("filter_1", "F", Field.Store.NO));
        docs.add(document);
        document = new Document();
        document.add(new StringField("__type", "parent", Field.Store.NO));
        document.add(createField("field1", 8, Field.Store.NO));
        docs.add(document);
        writer.addDocuments(docs);
        writer.commit();

        // Some garbage docs, just to check if the NestedFieldComparator can deal with this.
        document = new Document();
        document.add(new StringField("fieldXXX", "x", Field.Store.NO));
        writer.addDocument(document);
        document = new Document();
        document.add(new StringField("fieldXXX", "x", Field.Store.NO));
        writer.addDocument(document);
        document = new Document();
        document.add(new StringField("fieldXXX", "x", Field.Store.NO));
        writer.addDocument(document);

        SortMode sortMode = SortMode.SUM;
        IndexSearcher searcher = new IndexSearcher(DirectoryReader.open(writer, false));
        IndexFieldData.XFieldComparatorSource innerFieldComparator = createInnerFieldComparator("field2", sortMode);
        Filter parentFilter = new TermFilter(new Term("__type", "parent"));
        Filter childFilter = new NotFilter(parentFilter);
        NestedFieldComparatorSource nestedComparatorSource = new NestedFieldComparatorSource(sortMode, innerFieldComparator, parentFilter, childFilter);
        ToParentBlockJoinQuery query = new ToParentBlockJoinQuery(new XFilteredQuery(new MatchAllDocsQuery(), childFilter), new CachingWrapperFilter(parentFilter), ScoreMode.None);

        Sort sort = new Sort(new SortField("field2", nestedComparatorSource));
        TopFieldDocs topDocs = searcher.search(query, 5, sort);
        assertThat(topDocs.totalHits, equalTo(7));
        assertThat(topDocs.scoreDocs.length, equalTo(5));
        assertThat(topDocs.scoreDocs[0].doc, equalTo(11));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[0]).fields[0]).intValue(), equalTo(7));
        assertThat(topDocs.scoreDocs[1].doc, equalTo(7));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[1]).fields[0]).intValue(), equalTo(8));
        assertThat(topDocs.scoreDocs[2].doc, equalTo(3));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[2]).fields[0]).intValue(), equalTo(9));
        assertThat(topDocs.scoreDocs[3].doc, equalTo(15));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[3]).fields[0]).intValue(), equalTo(10));
        assertThat(topDocs.scoreDocs[4].doc, equalTo(19));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[4]).fields[0]).intValue(), equalTo(11));

        sort = new Sort(new SortField("field2", nestedComparatorSource, true));
        topDocs = searcher.search(query, 5, sort);
        assertThat(topDocs.totalHits, equalTo(7));
        assertThat(topDocs.scoreDocs.length, equalTo(5));
        assertThat(topDocs.scoreDocs[0].doc, equalTo(28));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[0]).fields[0]).intValue(), equalTo(13));
        assertThat(topDocs.scoreDocs[1].doc, equalTo(23));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[1]).fields[0]).intValue(), equalTo(12));
        assertThat(topDocs.scoreDocs[2].doc, equalTo(19));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[2]).fields[0]).intValue(), equalTo(11));
        assertThat(topDocs.scoreDocs[3].doc, equalTo(15));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[3]).fields[0]).intValue(), equalTo(10));
        assertThat(topDocs.scoreDocs[4].doc, equalTo(3));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[4]).fields[0]).intValue(), equalTo(9));

        childFilter = new AndFilter(Arrays.asList(new NotFilter(parentFilter), new TermFilter(new Term("filter_1", "T"))));
        nestedComparatorSource = new NestedFieldComparatorSource(sortMode, innerFieldComparator, parentFilter, childFilter);
        query = new ToParentBlockJoinQuery(
                new XFilteredQuery(new MatchAllDocsQuery(), childFilter),
                new CachingWrapperFilter(parentFilter),
                ScoreMode.None
        );
        sort = new Sort(new SortField("field2", nestedComparatorSource, true));
        topDocs = searcher.search(query, 5, sort);
        assertThat(topDocs.totalHits, equalTo(6));
        assertThat(topDocs.scoreDocs.length, equalTo(5));
        assertThat(topDocs.scoreDocs[0].doc, equalTo(23));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[0]).fields[0]).intValue(), equalTo(12));
        assertThat(topDocs.scoreDocs[1].doc, equalTo(3));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[1]).fields[0]).intValue(), equalTo(9));
        assertThat(topDocs.scoreDocs[2].doc, equalTo(7));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[2]).fields[0]).intValue(), equalTo(8));
        assertThat(topDocs.scoreDocs[3].doc, equalTo(11));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[3]).fields[0]).intValue(), equalTo(7));
        assertThat(topDocs.scoreDocs[4].doc, equalTo(15));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[4]).fields[0]).intValue(), equalTo(3));

        sort = new Sort(new SortField("field2", nestedComparatorSource));
        topDocs = searcher.search(query, 5, sort);
        assertThat(topDocs.totalHits, equalTo(6));
        assertThat(topDocs.scoreDocs.length, equalTo(5));
        assertThat(topDocs.scoreDocs[0].doc, equalTo(15));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[0]).fields[0]).intValue(), equalTo(3));
        assertThat(topDocs.scoreDocs[1].doc, equalTo(28));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[1]).fields[0]).intValue(), equalTo(3));
        assertThat(topDocs.scoreDocs[2].doc, equalTo(11));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[2]).fields[0]).intValue(), equalTo(7));
        assertThat(topDocs.scoreDocs[3].doc, equalTo(7));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[3]).fields[0]).intValue(), equalTo(8));
        assertThat(topDocs.scoreDocs[4].doc, equalTo(3));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[4]).fields[0]).intValue(), equalTo(9));

        // Moved to method, because floating point based XFieldComparatorSource have different outcome for SortMode avg,
        // than integral number based implementations...
        assertAvgScoreMode(parentFilter, searcher, innerFieldComparator);
        searcher.getIndexReader().close();
    }

    protected void assertAvgScoreMode(Filter parentFilter, IndexSearcher searcher, IndexFieldData.XFieldComparatorSource innerFieldComparator) throws IOException {
        SortMode sortMode = SortMode.AVG;
        Filter childFilter = new NotFilter(parentFilter);
        NestedFieldComparatorSource nestedComparatorSource = new NestedFieldComparatorSource(sortMode, innerFieldComparator, parentFilter, childFilter);
        Query query = new ToParentBlockJoinQuery(new XFilteredQuery(new MatchAllDocsQuery(), childFilter), new CachingWrapperFilter(parentFilter), ScoreMode.None);
        Sort sort = new Sort(new SortField("field2", nestedComparatorSource));
        TopDocs topDocs = searcher.search(query, 5, sort);
        assertThat(topDocs.totalHits, equalTo(7));
        assertThat(topDocs.scoreDocs.length, equalTo(5));
        assertThat(topDocs.scoreDocs[0].doc, equalTo(7));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[0]).fields[0]).intValue(), equalTo(2));
        assertThat(topDocs.scoreDocs[1].doc, equalTo(11));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[1]).fields[0]).intValue(), equalTo(2));
        assertThat(topDocs.scoreDocs[2].doc, equalTo(3));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[2]).fields[0]).intValue(), equalTo(3));
        assertThat(topDocs.scoreDocs[3].doc, equalTo(15));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[3]).fields[0]).intValue(), equalTo(3));
        assertThat(topDocs.scoreDocs[4].doc, equalTo(19));
        assertThat(((Number) ((FieldDoc) topDocs.scoreDocs[4]).fields[0]).intValue(), equalTo(3));
    }

    protected abstract IndexableField createField(String name, int value, Field.Store store);

    protected abstract IndexFieldData.XFieldComparatorSource createInnerFieldComparator(String fieldName, SortMode sortMode);

}
