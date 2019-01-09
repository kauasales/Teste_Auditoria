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

package org.elasticsearch.search.aggregations.bucket.geogrid2;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.search.aggregations.InternalAggregations;

import java.io.IOException;

/**
 * Instances implement different hashing algorithms for geo-grid aggregations
 */
public interface GeoGridType {
    /**
     * Returns the name of the grid aggregation, e.g. "geohash"
     */
    String getName();

    /**
     * Returns default precision for the type, e.g. 5 for geohash
     */
    int getDefaultPrecision();

    /**
     * Parses precision string into an integer, e.g. "100km" into 4
     */
    int parsePrecisionString(String precision);

    /**
     * Validates precision for the given geo type, and throws an exception on error
     * @param precision value to validate
     * @return the original value if everything is ok
     */
    int validatePrecision(int precision);

    /**
     * Converts longitude/latitude into a bucket identifying hash value with the given precision
     * @return hash value
     */
    long calculateHash(double longitude, double latitude, int precision);

    /**
     * Decodes hash value into a string returned to the user
     * @param hash as generated by the {@link #calculateHash}
     * @return bucket ID as a string
     */
    String hashAsString(long hash);

    /**
     * Factory method to create a new bucket.
     */
    GeoGridBucket createBucket(long hashAsLong, long docCount, InternalAggregations aggregations);

    /**
     * Factory method to create a new bucket from a stream.
     */
    GeoGridBucket createBucket(StreamInput reader) throws IOException;
}
