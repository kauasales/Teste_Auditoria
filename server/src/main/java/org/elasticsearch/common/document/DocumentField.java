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

package org.elasticsearch.common.document;

import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ToXContentFragment;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.search.SearchHit;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import static org.elasticsearch.common.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.elasticsearch.common.xcontent.XContentParserUtils.parseFieldsValue;

/**
 * A single field name and values part of {@link SearchHit} and {@link GetResult}.
 *
 * @see SearchHit
 * @see GetResult
 */
public class DocumentField implements Writeable, ToXContentFragment, Iterable<Object> {

    private final String name;
    private final List<Object> values;
    private final boolean isMetaField; // if the field is a meta-data field

    public DocumentField(StreamInput in) throws IOException {
        name = in.readString();
        int size = in.readVInt();
        values = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            values.add(in.readGenericValue());
        }
        if (in.getVersion().onOrAfter(Version.V_8_0_0)) {
            isMetaField = in.readBoolean();
        } else {
            isMetaField = MapperService.isMetadataFieldSt(name); // TODO: remove in 9.0
        }
    }

    public DocumentField(String name, List<Object> values, boolean isMetaField) {
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.values = Objects.requireNonNull(values, "values must not be null");
        this.isMetaField = isMetaField;
    }

    /**
     * The name of the field.
     */
    public String getName() {
        return name;
    }

    /**
     * The first value of the hit.
     */
    @SuppressWarnings("unchecked")
    public <V> V getValue() {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return (V) values.get(0);
    }

    /**
     * The field values.
     */
    public List<Object> getValues() {
        return values;
    }

    /**
    * @return The field is a metadata field
    */
    public boolean isMetadataField() {
        return isMetaField;
    }

    @Override
    public Iterator<Object> iterator() {
        return values.iterator();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeVInt(values.size());
        for (Object obj : values) {
            out.writeGenericValue(obj);
        }
        if (out.getVersion().onOrAfter(Version.V_8_0_0)) {
            out.writeBoolean(isMetaField);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        // we don't convert isMetaField to XContent,
        // the way fields are organized in a document defines if they are metafields
        builder.startArray(name);
        for (Object value : values) {
            // this call doesn't really need to support writing any kind of object.
            // Stored fields values are converted using MappedFieldType#valueForDisplay.
            // As a result they can either be Strings, Numbers, or Booleans, that's
            // all.
            builder.value(value);
        }
        builder.endArray();
        return builder;
    }

    public static DocumentField fromXContent(XContentParser parser, boolean isMetaField) throws IOException {
        ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser::getTokenLocation);
        String fieldName = parser.currentName();
        XContentParser.Token token = parser.nextToken();
        ensureExpectedToken(XContentParser.Token.START_ARRAY, token, parser::getTokenLocation);
        List<Object> values = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            values.add(parseFieldsValue(parser));
        }
        return new DocumentField(fieldName, values, isMetaField);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        DocumentField objects = (DocumentField) o;
        return Objects.equals(name, objects.name) && Objects.equals(values, objects.values) && isMetaField == objects.isMetaField;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, values, isMetaField);
    }

    @Override
    public String toString() {
        return "DocumentField{" +
                "name='" + name + '\'' +
                ", values=" + values  +
                 ", is meta-field=" + isMetaField +
            '}';
    }
}
