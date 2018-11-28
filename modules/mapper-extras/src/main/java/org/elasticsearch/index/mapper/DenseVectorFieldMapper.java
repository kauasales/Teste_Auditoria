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

package org.elasticsearch.index.mapper;

import org.apache.lucene.document.BinaryDocValuesField;
import org.apache.lucene.index.IndexOptions;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.search.DocValuesFieldExistsQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.util.ArrayUtil;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentParser.Token;
import org.elasticsearch.index.fielddata.IndexFieldData;
import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.search.DocValueFormat;
import org.joda.time.DateTimeZone;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * A {@link FieldMapper} for indexing a dense vector of floats.
 */

public class DenseVectorFieldMapper extends FieldMapper implements ArrayValueMapperParser {

    public static final String CONTENT_TYPE = "dense_vector";
    public static int MAX_DIMS_COUNT = 500; //maximum allowed number of dimensions
    private static final int INT_BYTES = Integer.BYTES;

    public static class Defaults {
        public static final MappedFieldType FIELD_TYPE = new DenseVectorFieldType();

        static {
            FIELD_TYPE.setTokenized(false);
            FIELD_TYPE.setIndexOptions(IndexOptions.NONE);
            FIELD_TYPE.setHasDocValues(true);
            FIELD_TYPE.setOmitNorms(true);
            FIELD_TYPE.freeze();
        }
    }

    public static class Builder extends FieldMapper.Builder<Builder, DenseVectorFieldMapper> {

        public Builder(String name) {
            super(name, Defaults.FIELD_TYPE, Defaults.FIELD_TYPE);
            builder = this;
        }

        @Override
        public DenseVectorFieldType fieldType() {
            return (DenseVectorFieldType) super.fieldType();
        }

        @Override
        public DenseVectorFieldMapper build(BuilderContext context) {
            setupFieldType(context);
            return new DenseVectorFieldMapper(
                    name, fieldType, defaultFieldType,
                    context.indexSettings(), multiFieldsBuilder.build(this, context), copyTo);
        }
    }

    public static class TypeParser implements Mapper.TypeParser {
        @Override
        public Mapper.Builder<?,?> parse(String name, Map<String, Object> node, ParserContext parserContext) throws MapperParsingException {
            DenseVectorFieldMapper.Builder builder = new DenseVectorFieldMapper.Builder(name);
            return builder;
        }
    }

    public static final class DenseVectorFieldType extends MappedFieldType {

        public DenseVectorFieldType() {}

        protected DenseVectorFieldType(DenseVectorFieldType ref) {
            super(ref);
        }

        public DenseVectorFieldType clone() {
            return new DenseVectorFieldType(this);
        }

        @Override
        public String typeName() {
            return CONTENT_TYPE;
        }

        @Override
        public DocValueFormat docValueFormat(String format, DateTimeZone timeZone) {
            throw new UnsupportedOperationException("[dense_vector] field doesn't support doc values");
        }

        @Override
        public Query existsQuery(QueryShardContext context) {
            return new DocValuesFieldExistsQuery(name());
        }

        @Override
        public IndexFieldData.Builder fielddataBuilder(String fullyQualifiedIndexName) {
            throw new UnsupportedOperationException("[dense_vector] fields doen't support sorting, scripting or aggregating");
        }

        @Override
        public Query termQuery(Object value, QueryShardContext context) {
            throw new UnsupportedOperationException("Queries on [dense_vector] fields are not supported");
        }
    }

    private DenseVectorFieldMapper(String simpleName, MappedFieldType fieldType, MappedFieldType defaultFieldType,
                                   Settings indexSettings, MultiFields multiFields, CopyTo copyTo) {
        super(simpleName, fieldType, defaultFieldType, indexSettings, multiFields, copyTo);
        assert fieldType.indexOptions().compareTo(IndexOptions.DOCS_AND_FREQS) <= 0;
    }

    @Override
    protected DenseVectorFieldMapper clone() {
        return (DenseVectorFieldMapper) super.clone();
    }

    @Override
    public DenseVectorFieldType fieldType() {
        return (DenseVectorFieldType) super.fieldType();
    }

    @Override
    public void parse(ParseContext context) throws IOException {
        if (context.externalValueSet()) {
            throw new IllegalArgumentException("[dense_vector] field can't be used in multi-fields");
        }

        // encode array of floats as array of integers and store into buf
        byte[] buf = new byte[0];
        int offset = 0;
        int dim = 0;
        for (Token token = context.parser().nextToken(); token != Token.END_ARRAY; token = context.parser().nextToken()) {
            if (token == Token.VALUE_NUMBER) {
                float value = context.parser().floatValue(true);
                if (buf.length < (offset + INT_BYTES)) {
                    buf = ArrayUtil.grow(buf, (offset + INT_BYTES));
                }
                int intValue = Float.floatToIntBits(value);
                buf[offset] =  (byte) (intValue >> 24);
                buf[offset+1] = (byte) (intValue >> 16);
                buf[offset+2] = (byte) (intValue >>  8);
                buf[offset+3] = (byte) intValue;
                offset += INT_BYTES;
                dim++;
                if (dim >= MAX_DIMS_COUNT) {
                    throw new IllegalArgumentException(
                        "[dense_vector] field has exceeded the maximum allowed number of dimensions of :[" + MAX_DIMS_COUNT + "]");
                }
            } else {
                throw new IllegalArgumentException("[dense_vector] field takes an array of floats, but got unexpected token " + token);
            }
        }
        BinaryDocValuesField field = new BinaryDocValuesField(fieldType().name(), new BytesRef(buf, 0, offset));
        if (context.doc().getByKey(fieldType().name()) != null) {
            throw new IllegalArgumentException("[dense_vector] field doesn't not support indexing multiple values for the same " +
                "field [" + name() + "] in the same document");
        }
        context.doc().addWithKey(fieldType().name(), field);
    }

    @Override
    protected void parseCreateField(ParseContext context, List<IndexableField> fields) {
        throw new AssertionError("parse is implemented directly");
    }

    @Override
    protected String contentType() {
        return CONTENT_TYPE;
    }


    //**************STATIC HELPER METHODS***********************************
    // Decodes a BytesRef into an array of floats
    public static float[] decodeVector(BytesRef vectorBR) {
        int dimCount = (vectorBR.length - vectorBR.offset) / INT_BYTES;
        float[] vector = new float[dimCount];
        int offset = vectorBR.offset;
        for (int dim = 0; dim < dimCount; dim++) {
            int intValue = ((vectorBR.bytes[offset] & 0xFF) << 24)   |
                ((vectorBR.bytes[offset+1] & 0xFF) << 16) |
                ((vectorBR.bytes[offset+2] & 0xFF) <<  8) |
                (vectorBR.bytes[offset+3] & 0xFF);
            vector[dim] = Float.intBitsToFloat(intValue);
            offset = offset + INT_BYTES;
        }
        return vector;
    }
}
