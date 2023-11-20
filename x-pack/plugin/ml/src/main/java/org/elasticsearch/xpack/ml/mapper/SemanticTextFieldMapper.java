/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.ml.mapper;

import org.apache.lucene.search.Query;
import org.elasticsearch.index.mapper.DocumentParserContext;
import org.elasticsearch.index.mapper.FieldMapper;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.index.mapper.MapperBuilderContext;
import org.elasticsearch.index.mapper.SimpleMappedFieldType;
import org.elasticsearch.index.mapper.SourceValueFetcher;
import org.elasticsearch.index.mapper.TextSearchInfo;
import org.elasticsearch.index.mapper.ValueFetcher;
import org.elasticsearch.index.mapper.vectors.SparseVectorFieldMapper;
import org.elasticsearch.index.mapper.vectors.SparseVectorFieldMapper.SparseVectorFieldType;
import org.elasticsearch.index.query.SearchExecutionContext;

import java.io.IOException;
import java.util.Map;

/** A {@link FieldMapper} for full-text fields. */
public class SemanticTextFieldMapper extends FieldMapper {

    public static final String CONTENT_TYPE = "semantic_text";

    public static final String TEXT_SUBFIELD_NAME = "text";
    public static final String SPARSE_VECTOR_SUBFIELD_NAME = "inference";

    private static SemanticTextFieldMapper toType(FieldMapper in) {
        return (SemanticTextFieldMapper) in;
    }

    public static class Builder extends FieldMapper.Builder {

        final Parameter<String> modelId = Parameter.stringParam("model_id", false, m -> toType(m).modelId, null).addValidator(value -> {
            if (value == null) {
                // TODO check the model exists
                throw new IllegalArgumentException("field [model_id] must be specified");
            }
        });

        private final Parameter<Map<String, String>> meta = Parameter.metaParam();

        public Builder(String name) {
            super(name);
        }

        public Builder modelId(String modelId) {
            this.modelId.setValue(modelId);
            return this;
        }

        @Override
        protected Parameter<?>[] getParameters() {
            return new Parameter<?>[] { modelId, meta };
        }

        private SemanticTextFieldType buildFieldType(MapperBuilderContext context) {
            return new SemanticTextFieldType(context.buildFullName(name), modelId.getValue(), meta.getValue());
        }

        @Override
        public SemanticTextFieldMapper build(MapperBuilderContext context) {
            String fullName = context.buildFullName(name);
            String subfieldName = fullName + "." + SPARSE_VECTOR_SUBFIELD_NAME;
            SparseVectorFieldMapper sparseVectorFieldMapper = new SparseVectorFieldMapper.Builder(subfieldName).build(context);
            return new SemanticTextFieldMapper(
                name(),
                new SemanticTextFieldType(name(), modelId.getValue(), meta.getValue()),
                modelId.getValue(),
                sparseVectorFieldMapper,
                copyTo,
                this
            );
        }
    }

    public static final TypeParser PARSER = new TypeParser((n, c) -> new Builder(n), notInMultiFields(CONTENT_TYPE));

    public static class SemanticTextFieldType extends SimpleMappedFieldType {

        private final SparseVectorFieldType sparseVectorFieldType;

        private final String modelId;

        public SemanticTextFieldType(String name, String modelId, Map<String, String> meta) {
            super(name, true, false, false, TextSearchInfo.NONE, meta);
            this.sparseVectorFieldType = new SparseVectorFieldType(name + "." + SPARSE_VECTOR_SUBFIELD_NAME, meta);
            this.modelId = modelId;
        }

        public String modelId() {
            return modelId;
        }

        public SparseVectorFieldType getSparseVectorFieldType() {
            return this.sparseVectorFieldType;
        }

        @Override
        public String typeName() {
            return CONTENT_TYPE;
        }

        public String getInferenceModel() {
            return modelId;
        }

        @Override
        public ValueFetcher valueFetcher(SearchExecutionContext context, String format) {
            return SourceValueFetcher.identity(name(), context, format);
        }

        @Override
        public Query termQuery(Object value, SearchExecutionContext context) {
            return sparseVectorFieldType.termQuery(value, context);
        }

        @Override
        public Query existsQuery(SearchExecutionContext context) {
            return sparseVectorFieldType.existsQuery(context);
        }
    }

    private final String modelId;
    private final SparseVectorFieldMapper sparseVectorFieldMapper;

    private SemanticTextFieldMapper(
        String simpleName,
        MappedFieldType mappedFieldType,
        String modelId,
        SparseVectorFieldMapper sparseVectorFieldMapper,
        CopyTo copyTo,
        Builder builder
    ) {
        super(simpleName, mappedFieldType, MultiFields.empty(), copyTo);
        this.modelId = modelId;
        this.sparseVectorFieldMapper = sparseVectorFieldMapper;
    }

    @Override
    public FieldMapper.Builder getMergeBuilder() {
        return new Builder(simpleName()).init(this);
    }

    @Override
    protected void parseCreateField(DocumentParserContext context) throws IOException {
        context.parser().textOrNull();
    }

    @Override
    protected String contentType() {
        return CONTENT_TYPE;
    }

    @Override
    public SemanticTextFieldType fieldType() {
        return (SemanticTextFieldType) super.fieldType();
    }
}
