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

package org.elasticsearch.search.aggregations.bucket.geogrid;

import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;

public class ParsedQuadkeyGrid extends ParsedGeoGrid {

    private static ObjectParser<ParsedGeoGrid, Void> PARSER = createParser(ParsedQuadkeyGrid::new,
        ParsedQuadkeyGridBucket::fromXContent, ParsedQuadkeyGridBucket::fromXContent);

    public static ParsedGeoGrid fromXContent(XContentParser parser, String name) throws IOException {
        ParsedGeoGrid aggregation = PARSER.parse(parser, null);
        aggregation.setName(name);
        return aggregation;
    }

    @Override
    public String getType() {
        return QuadkeyGridAggregationBuilder.NAME;
    }
}
