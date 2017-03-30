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

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.DocValues;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.RandomAccessOrds;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.search.SortField;
import org.apache.lucene.search.SortedSetSelector;
import org.apache.lucene.search.SortedSetSortField;
import org.apache.lucene.util.Accountable;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.fielddata.AtomicOrdinalsFieldData;
import org.elasticsearch.index.fielddata.IndexFieldData;
import org.elasticsearch.index.fielddata.IndexFieldDataCache;
import org.elasticsearch.index.fielddata.IndexOrdinalsFieldData;
import org.elasticsearch.index.fielddata.fieldcomparator.BytesRefFieldComparatorSource;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.index.mapper.TextFieldMapper;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.search.MultiValueMode;

import java.util.Collection;
import java.util.Collections;

public class IndexIndexFieldData extends AbstractIndexOrdinalsFieldData {

    public static class Builder implements IndexFieldData.Builder {

        @Override
        public IndexFieldData<?> build(IndexSettings indexSettings, MappedFieldType fieldType, IndexFieldDataCache cache,
                CircuitBreakerService breakerService, MapperService mapperService) {
            return new IndexIndexFieldData(indexSettings, fieldType.name());
        }

    }

    private static class IndexAtomicFieldData extends AbstractAtomicOrdinalsFieldData {

        private final String index;

        IndexAtomicFieldData(String index) {
            super(DEFAULT_SCRIPT_FUNCTION);
            this.index = index;
        }

        @Override
        public long ramBytesUsed() {
            return 0;
        }

        @Override
        public Collection<Accountable> getChildResources() {
            return Collections.emptyList();
        }

        @Override
        public RandomAccessOrds getOrdinalsValues() {
            final BytesRef term = new BytesRef(index);
            final SortedDocValues sortedValues = new SortedDocValues() {

                @Override
                public BytesRef lookupOrd(int ord) {
                    return term;
                }

                @Override
                public int getValueCount() {
                    return 1;
                }

                @Override
                public int getOrd(int docID) {
                    return 0;
                }
            };
            return (RandomAccessOrds) DocValues.singleton(sortedValues);
        }

        @Override
        public void close() {
        }

    }

    private final AtomicOrdinalsFieldData atomicFieldData;

    private IndexIndexFieldData(IndexSettings indexSettings, String name) {
        super(indexSettings, name, null, null,
                TextFieldMapper.Defaults.FIELDDATA_MIN_FREQUENCY,
                TextFieldMapper.Defaults.FIELDDATA_MAX_FREQUENCY,
                TextFieldMapper.Defaults.FIELDDATA_MIN_SEGMENT_SIZE);
        atomicFieldData = new IndexAtomicFieldData(index().getName());
    }

    @Override
    public void clear() {
    }

    @Override
    public final AtomicOrdinalsFieldData load(LeafReaderContext context) {
        return atomicFieldData;
    }

    @Override
    public AtomicOrdinalsFieldData loadDirect(LeafReaderContext context)
            throws Exception {
        return atomicFieldData;
    }

    @Override
    public SortField sortField(@Nullable Object missingValue, MultiValueMode sortMode, XFieldComparatorSource.Nested nested, boolean reverse) {
        XFieldComparatorSource source = new BytesRefFieldComparatorSource(this, missingValue, sortMode, nested);
        if (nested != null ||
            (sortMode != MultiValueMode.MAX && sortMode != MultiValueMode.MIN) ||
            (source.sortMissingFirst(missingValue) == false && source.sortMissingLast(missingValue) == false)) {
            return new SortField(getFieldName(), source, reverse);
        }
        SortField sortField = new SortedSetSortField(getFieldName(), reverse,
            sortMode == MultiValueMode.MAX ? SortedSetSelector.Type.MAX : SortedSetSelector.Type.MIN);
        sortField.setMissingValue(source.sortMissingLast(missingValue) ^ reverse ?
            SortedSetSortField.STRING_LAST : SortedSetSortField.STRING_FIRST);
        return sortField;
    }

    @Override
    public IndexOrdinalsFieldData loadGlobal(DirectoryReader indexReader) {
        return this;
    }

    @Override
    public IndexOrdinalsFieldData localGlobalDirect(DirectoryReader indexReader) throws Exception {
        return loadGlobal(indexReader);
    }

}
