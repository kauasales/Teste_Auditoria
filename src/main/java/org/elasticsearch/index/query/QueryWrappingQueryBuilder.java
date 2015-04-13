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

import org.apache.lucene.search.Query;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Temporary wrapper for keeping pre-parsed lucene query in a QueryBuilder field in nested queries.
 * Can be removed after query refactoring is done.
 */
public class QueryWrappingQueryBuilder extends BaseQueryBuilder {
    
    private Query query;

    public QueryWrappingQueryBuilder(Query query) {
        this.query = query;
    }

    @Override
    protected void doXContent(XContentBuilder builder, Params params) throws IOException {
        throw new org.apache.commons.lang3.NotImplementedException("Not Implemented");
    }

    @Override
    public Query toQuery(QueryParseContext parseContext) throws QueryParsingException, IOException {
        return this.query;
    }

}
