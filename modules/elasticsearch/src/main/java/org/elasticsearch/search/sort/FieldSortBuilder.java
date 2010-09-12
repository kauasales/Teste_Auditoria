/*
 * Licensed to Elastic Search and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Elastic Search licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

package org.elasticsearch.search.sort;

import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * A sort builder to sort based on a document field.
 *
 * @author kimchy (shay.banon)
 */
public class FieldSortBuilder extends SortBuilder {

    private final String fieldName;

    private SortOrder order;

    /**
     * Constructs a new sort based on a document field.
     *
     * @param fieldName The field name.
     */
    public FieldSortBuilder(String fieldName) {
        this.fieldName = fieldName;
    }

    /**
     * The order of sorting. Defaults to {@link SortOrder#ASC}.
     */
    public FieldSortBuilder order(SortOrder order) {
        this.order = order;
        return this;
    }

    @Override public void toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(fieldName);
        if (order == SortOrder.DESC) {
            builder.field("reverse", true);
        }
        builder.endObject();
    }
}
