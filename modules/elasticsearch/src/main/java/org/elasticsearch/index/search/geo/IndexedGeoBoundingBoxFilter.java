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

package org.elasticsearch.index.search.geo;

import org.apache.lucene.index.IndexReader;
import org.apache.lucene.search.DocIdSet;
import org.apache.lucene.search.Filter;
import org.apache.lucene.util.OpenBitSet;
import org.elasticsearch.ElasticSearchIllegalArgumentException;
import org.elasticsearch.index.mapper.geo.GeoPointFieldMapper;

import java.io.IOException;

/**
 */
public class IndexedGeoBoundingBoxFilter {

    public static Filter create(Point topLeft, Point bottomRight, GeoPointFieldMapper fieldMapper) {
        if (!fieldMapper.isEnableLatLon()) {
            throw new ElasticSearchIllegalArgumentException("lat/lon is not enabled (indexed) for field [" + fieldMapper.name() + "], can't use indexed filter on it");
        }
        //checks to see if bounding box crosses 180 degrees
        if (topLeft.lon > bottomRight.lon) {
            return new LeftGeoBoundingBoxFilter(topLeft, bottomRight, fieldMapper);
        } else {
            return new RightGeoBoundingBoxFilter(topLeft, bottomRight, fieldMapper);
        }
    }

    static class LeftGeoBoundingBoxFilter extends Filter {

        final Filter lonFilter1;
        final Filter lonFilter2;
        final Filter latFilter;

        public LeftGeoBoundingBoxFilter(Point topLeft, Point bottomRight, GeoPointFieldMapper fieldMapper) {
            lonFilter1 = fieldMapper.lonMapper().rangeFilter(null, bottomRight.lon, true, true);
            lonFilter2 = fieldMapper.lonMapper().rangeFilter(topLeft.lon, null, true, true);
            latFilter = fieldMapper.latMapper().rangeFilter(bottomRight.lat, topLeft.lat, true, true);
        }

        @Override public OpenBitSet getDocIdSet(IndexReader reader) throws IOException {
            OpenBitSet main;
            DocIdSet set = lonFilter1.getDocIdSet(reader);
            if (set == null || set == DocIdSet.EMPTY_DOCIDSET) {
                main = null;
            } else {
                main = (OpenBitSet) set;
            }

            set = lonFilter2.getDocIdSet(reader);
            if (set == null || set == DocIdSet.EMPTY_DOCIDSET) {
                if (main == null) {
                    return null;
                } else {
                    // nothing to do here, we remain with the main one
                }
            } else {
                if (main == null) {
                    main = (OpenBitSet) set;
                } else {
                    main.or((OpenBitSet) set);
                }
            }

            set = latFilter.getDocIdSet(reader);
            if (set == null || set == DocIdSet.EMPTY_DOCIDSET) {
                return null;
            }
            main.and((OpenBitSet) set);
            return main;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            LeftGeoBoundingBoxFilter that = (LeftGeoBoundingBoxFilter) o;

            if (latFilter != null ? !latFilter.equals(that.latFilter) : that.latFilter != null) return false;
            if (lonFilter1 != null ? !lonFilter1.equals(that.lonFilter1) : that.lonFilter1 != null) return false;
            if (lonFilter2 != null ? !lonFilter2.equals(that.lonFilter2) : that.lonFilter2 != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = lonFilter1 != null ? lonFilter1.hashCode() : 0;
            result = 31 * result + (lonFilter2 != null ? lonFilter2.hashCode() : 0);
            result = 31 * result + (latFilter != null ? latFilter.hashCode() : 0);
            return result;
        }
    }

    static class RightGeoBoundingBoxFilter extends Filter {

        final Filter lonFilter;
        final Filter latFilter;

        public RightGeoBoundingBoxFilter(Point topLeft, Point bottomRight, GeoPointFieldMapper fieldMapper) {
            lonFilter = fieldMapper.lonMapper().rangeFilter(topLeft.lon, bottomRight.lon, true, true);
            latFilter = fieldMapper.latMapper().rangeFilter(bottomRight.lat, topLeft.lat, true, true);
        }

        @Override public OpenBitSet getDocIdSet(IndexReader reader) throws IOException {
            OpenBitSet main;
            DocIdSet set = lonFilter.getDocIdSet(reader);
            if (set == null || set == DocIdSet.EMPTY_DOCIDSET) {
                return null;
            }
            main = (OpenBitSet) set;
            set = latFilter.getDocIdSet(reader);
            if (set == null || set == DocIdSet.EMPTY_DOCIDSET) {
                return null;
            }
            main.and((OpenBitSet) set);
            return main;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            RightGeoBoundingBoxFilter that = (RightGeoBoundingBoxFilter) o;

            if (latFilter != null ? !latFilter.equals(that.latFilter) : that.latFilter != null) return false;
            if (lonFilter != null ? !lonFilter.equals(that.lonFilter) : that.lonFilter != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = lonFilter != null ? lonFilter.hashCode() : 0;
            result = 31 * result + (latFilter != null ? latFilter.hashCode() : 0);
            return result;
        }
    }
}
