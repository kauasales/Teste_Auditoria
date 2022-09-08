/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package org.elasticsearch.search.lookup;

import org.apache.lucene.index.LeafReaderContext;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.util.Maps;
import org.elasticsearch.index.fielddata.IndexFieldData;
import org.elasticsearch.index.fielddata.ScriptDocValues;
import org.elasticsearch.index.fielddata.SourceValueFetcherIndexFieldData;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.script.field.DocValuesScriptFieldFactory;
import org.elasticsearch.script.field.Field;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.elasticsearch.index.mapper.MappedFieldType.FielddataOperation.SCRIPT;
import static org.elasticsearch.index.mapper.MappedFieldType.FielddataOperation.SEARCH;

public class LeafDocLookup implements Map<String, ScriptDocValues<?>> {

    private final Function<String, MappedFieldType> fieldTypeLookup;
    private final BiFunction<MappedFieldType, MappedFieldType.FielddataOperation, IndexFieldData<?>> fieldDataLookup;
    private final LeafReaderContext reader;

    private int docId = -1;

    private final Map<String, DocValuesScriptFieldFactory> fieldFactoryCache = Maps.newMapWithExpectedSize(4);
    private final Map<String, DocValuesScriptFieldFactory> docFactoryCache = Maps.newMapWithExpectedSize(4);

    LeafDocLookup(
        Function<String, MappedFieldType> fieldTypeLookup,
        BiFunction<MappedFieldType, MappedFieldType.FielddataOperation, IndexFieldData<?>> fieldDataLookup,
        LeafReaderContext reader
    ) {
        this.fieldTypeLookup = fieldTypeLookup;
        this.fieldDataLookup = fieldDataLookup;
        this.reader = reader;
    }

    public void setDocument(int docId) {
        this.docId = docId;
    }

    protected DocValuesScriptFieldFactory getScriptFieldFactory(String fieldName, boolean isFieldAccess) {
        final MappedFieldType fieldType = fieldTypeLookup.apply(fieldName);

        if (fieldType == null) {
            throw new IllegalArgumentException("No field found for [" + fieldName + "] in mapping");
        }

        // Load the field data on behalf of the script. Otherwise, it would require
        // additional permissions to deal with pagedbytes/ramusagestimator/etc.
        return AccessController.doPrivileged(new PrivilegedAction<DocValuesScriptFieldFactory>() {
            @Override
            public DocValuesScriptFieldFactory run() {
                DocValuesScriptFieldFactory factory = null;
                IndexFieldData<?> indexFieldData = fieldDataLookup.apply(fieldType, isFieldAccess ? SCRIPT : SEARCH);

                if (isFieldAccess) {
                    DocValuesScriptFieldFactory docFactory = docFactoryCache.get(fieldName);

                    if (docFactory != null && indexFieldData instanceof SourceValueFetcherIndexFieldData == false) {
                        factory = docFactory;
                    } else {
                        factory = indexFieldData.load(reader).getScriptFieldFactory(fieldName);
                    }

                    fieldFactoryCache.put(fieldName, factory);
                } else {
                    DocValuesScriptFieldFactory fieldFactory = fieldFactoryCache.get(fieldName);

                    if (fieldFactory != null) {
                        IndexFieldData<?> fieldIndexFieldData = fieldDataLookup.apply(fieldType, SCRIPT);

                        if (fieldIndexFieldData instanceof SourceValueFetcherIndexFieldData == false) {
                            factory = fieldFactory;
                        }
                    }

                    if (factory == null) {
                        factory = indexFieldData.load(reader).getScriptFieldFactory(fieldName);
                    }

                    docFactoryCache.put(fieldName, factory);
                }

                return factory;
            }
        });
    }

    public Field<?> getScriptField(String fieldName) {
        DocValuesScriptFieldFactory factory = fieldFactoryCache.get(fieldName);

        if (factory == null) {
            factory = getScriptFieldFactory(fieldName, true);
        }

        try {
            factory.setNextDocId(docId);
        } catch (IOException ioe) {
            throw ExceptionsHelper.convertToElastic(ioe);
        }

        return factory.toScriptField();
    }

    @Override
    public ScriptDocValues<?> get(Object key) {
        String fieldName = key.toString();
        DocValuesScriptFieldFactory factory = docFactoryCache.get(fieldName);

        if (factory == null) {
            factory = getScriptFieldFactory(key.toString(), false);
        }

        try {
            factory.setNextDocId(docId);
        } catch (IOException ioe) {
            throw ExceptionsHelper.convertToElastic(ioe);
        }

        return factory.toScriptDocValues();
    }

    @Override
    public boolean containsKey(Object key) {
        String fieldName = key.toString();
        return fieldTypeLookup.apply(fieldName) != null;
    }

    @Override
    public int size() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isEmpty() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsValue(Object value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScriptDocValues<?> put(String key, ScriptDocValues<?> value) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScriptDocValues<?> remove(Object key) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void putAll(Map<? extends String, ? extends ScriptDocValues<?>> m) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<String> keySet() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Collection<ScriptDocValues<?>> values() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<Map.Entry<String, ScriptDocValues<?>>> entrySet() {
        throw new UnsupportedOperationException();
    }
}
