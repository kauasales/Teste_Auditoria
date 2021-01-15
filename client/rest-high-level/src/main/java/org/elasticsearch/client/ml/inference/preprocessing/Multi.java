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

package org.elasticsearch.client.ml.inference.preprocessing;


import java.io.IOException;
import java.util.List;
import java.util.Objects;

import org.elasticsearch.client.ml.inference.NamedXContentObjectHelper;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

/**
 * Multi-PreProcessor for chaining together multiple processors
 */
public class Multi implements PreProcessor {

    public static final String NAME = "multi_encoding";
    public static final ParseField PROCESSORS = new ParseField("processors");
    public static final ParseField CUSTOM = new ParseField("custom");

    @SuppressWarnings("unchecked")
    public static final ConstructingObjectParser<Multi, Void> PARSER = new ConstructingObjectParser<>(
        NAME,
        true,
        a -> new Multi((List<PreProcessor>)a[0], (Boolean)a[1]));
    static {
        PARSER.declareNamedObjects(ConstructingObjectParser.constructorArg(),
            (p, c, n) -> p.namedObject(PreProcessor.class, n, null),
            (_unused) -> {/* Does not matter client side*/ },
            PROCESSORS);
        PARSER.declareBoolean(ConstructingObjectParser.optionalConstructorArg(), CUSTOM);
    }

    public static Multi fromXContent(XContentParser parser) {
        return PARSER.apply(parser, null);
    }

    private final List<PreProcessor> processors;
    private final Boolean custom;

    Multi(List<PreProcessor> processors, Boolean custom) {
        this.processors = Objects.requireNonNull(processors, PROCESSORS.getPreferredName());
        this.custom = custom;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject();
        NamedXContentObjectHelper.writeNamedObjects(builder, params, true, PROCESSORS.getPreferredName(), processors);
        if (custom != null) {
            builder.field(CUSTOM.getPreferredName(), custom);
        }
        builder.endObject();
        return builder;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Multi multi = (Multi) o;
        return Objects.equals(multi.processors, processors) && Objects.equals(custom, multi.custom);
    }

    @Override
    public int hashCode() {
        return Objects.hash(custom, processors);
    }

    public static Builder builder(List<PreProcessor> processors) {
        return new Builder(processors);
    }

    public static class Builder {
        private final List<PreProcessor> processors;
        private Boolean custom;

        public Builder(List<PreProcessor> processors) {
            this.processors = processors;
        }

        public Builder setCustom(boolean custom) {
            this.custom = custom;
            return this;
        }

        public Multi build() {
            return new Multi(processors, custom);
        }
    }

}
