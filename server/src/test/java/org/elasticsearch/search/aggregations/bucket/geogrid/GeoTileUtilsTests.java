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

import org.elasticsearch.common.geo.GeoPoint;
import org.elasticsearch.test.ESTestCase;

import static org.elasticsearch.search.aggregations.bucket.geogrid.GeoTileUtils.MAX_ZOOM;
import static org.elasticsearch.search.aggregations.bucket.geogrid.GeoTileUtils.checkPrecisionRange;
import static org.elasticsearch.search.aggregations.bucket.geogrid.GeoTileUtils.hashToGeoPoint;
import static org.elasticsearch.search.aggregations.bucket.geogrid.GeoTileUtils.longEncode;
import static org.elasticsearch.search.aggregations.bucket.geogrid.GeoTileUtils.stringEncode;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.containsString;

public class GeoTileUtilsTests extends ESTestCase {

    private static final double GEOTILE_TOLERANCE = 1E-5D;

    /**
     * Precision validation should throw an error if its outside of the valid range.
     */
    public void testCheckPrecisionRange() {
        for (int i = 0; i <= 29; i++) {
            assertEquals(i, checkPrecisionRange(i));
        }
        IllegalArgumentException ex = expectThrows(IllegalArgumentException.class, () -> checkPrecisionRange(-1));
        assertThat(ex.getMessage(), containsString("Invalid geotile_grid precision of -1. Must be between 0 and 29."));
        ex = expectThrows(IllegalArgumentException.class, () -> checkPrecisionRange(30));
        assertThat(ex.getMessage(), containsString("Invalid geotile_grid precision of 30. Must be between 0 and 29."));
    }

    /**
     * A few hardcoded lat/lng/zoom hashing expectations
     */
    public void testLongEncode() {
        assertEquals(0, longEncode(0, 0, 0));
        assertEquals(0x3C00095540001CA5L, longEncode(30, 70, 15));
        assertEquals(0x77FFFF4580000000L, longEncode(179.999, 89.999, 29));
        assertEquals(0x740000BA7FFFFFFFL, longEncode(-179.999, -89.999, 29));
        assertEquals(0x0800000040000001L, longEncode(1, 1, 2));
        assertEquals(0x0C00000060000000L, longEncode(-20, 100, 3));
        assertEquals(0x71127D27C8ACA67AL, longEncode(13, -15, 28));
        assertEquals(0x4C0077776003A9ACL, longEncode(-12, 15, 19));

        expectThrows(IllegalArgumentException.class, () -> longEncode(0, 0, -1));
        expectThrows(IllegalArgumentException.class, () -> longEncode(-1, 0, MAX_ZOOM + 1));
    }

    private void assertGeoPointEquals(GeoPoint gp, final double longitude, final double latitude) {
        assertThat(gp.lon(), closeTo(longitude, GEOTILE_TOLERANCE));
        assertThat(gp.lat(), closeTo(latitude, GEOTILE_TOLERANCE));
    }

    public void testHashToGeoPoint() {
        assertGeoPointEquals(hashToGeoPoint("0/0/0"), 0.0, 0.0);
        assertGeoPointEquals(hashToGeoPoint("1/0/0"), -90.0, 66.51326044311186);
        assertGeoPointEquals(hashToGeoPoint("1/1/0"), 90.0, 66.51326044311186);
        assertGeoPointEquals(hashToGeoPoint("1/0/1"), -90.0, -66.51326044311186);
        assertGeoPointEquals(hashToGeoPoint("1/1/1"), 90.0, -66.51326044311186);
        assertGeoPointEquals(hashToGeoPoint("29/536870000/10"), 179.99938879162073, 85.05112817241982);
        assertGeoPointEquals(hashToGeoPoint("29/10/536870000"), -179.99999295920134, -85.0510760525731);

        expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint("0/-1/-1"));
        expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint("0/-1/1"));
        expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint("0/1/-1"));
        expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint("-1/0/0"));
        expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint((MAX_ZOOM + 1) + "/0/0"));

        for (int z = 0; z <= MAX_ZOOM; z++) {
            final int zoom = z;
            expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint(zoom + "/0"));
            expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint(zoom + "/0/0/0"));
            final int max_index = (int) Math.pow(2, zoom);
            expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint(zoom + "/0/" + max_index));
            expectThrows(IllegalArgumentException.class, () -> hashToGeoPoint(zoom + "/" + max_index + "/0"));
        }
    }

    /**
     * Make sure that hash produces the expected key, and that the key could be converted to hash via a GeoPoint
     */
    private void assertStrCodec(long hash, String key, int zoom) {
        assertEquals(key, stringEncode(hash));
        final GeoPoint gp = hashToGeoPoint(key);
        assertEquals(hash, longEncode(gp.lon(), gp.lat(), zoom));
    }

    /**
     * A few hardcoded lat/lng/zoom hashing expectations
     */
    public void testStringEncode() {
        assertStrCodec(0x0000000000000000L, "0/0/0", 0);
        assertStrCodec(0x3C00095540001CA5L, "15/19114/7333", 15);
        assertStrCodec(0x77FFFF4580000000L, "29/536869420/0", 29);
        assertStrCodec(0x740000BA7FFFFFFFL, "29/1491/536870911", 29);
        assertStrCodec(0x0800000040000001L, "2/2/1", 2);
        assertStrCodec(0x0C00000060000000L, "3/3/0", 3);
        assertStrCodec(0x71127D27C8ACA67AL, "28/143911230/145532538", 28);
        assertStrCodec(0x4C0077776003A9ACL, "19/244667/240044", 19);

        expectThrows(IllegalArgumentException.class, () -> stringEncode(-1L));
        expectThrows(IllegalArgumentException.class, () -> stringEncode(0x7800000000000000L)); // z=30
        expectThrows(IllegalArgumentException.class, () -> stringEncode(0x0000000000000001L)); // z=0,x=0,y=1
        expectThrows(IllegalArgumentException.class, () -> stringEncode(0x0000000020000000L)); // z=0,x=1,y=0

        for (int zoom = 0; zoom < 5; zoom++) {
            int maxTile = 1 << zoom;
            for (int x = 0; x < maxTile; x++) {
                for (int y = 0; y < maxTile; y++) {
                    String expectedTileIndex = zoom + "/" + x + "/" + y;
                    GeoPoint point = hashToGeoPoint(expectedTileIndex);
                    String actualTileIndex = stringEncode(longEncode(point.lon(), point.lat(), zoom));
                    assertEquals(expectedTileIndex, actualTileIndex);
                }
            }
        }
    }

    /**
     * Ensure that for all points at all supported precision levels that the long encoding of a geotile
     * is compatible with its String based counterpart
     */
    public void testGeoTileAsLongRoutines() {
        for (double lat = -90; lat <= 90; lat++) {
            for (double lng = -180; lng <= 180; lng++) {
                for (int p = 0; p <= 29; p++) {
                    long hash = longEncode(lng, lat, p);
                    if (p > 0) {
                        assertNotEquals(0, hash);
                    }

                    // GeoPoint would be in the center of the bucket, thus must produce the same hash
                    GeoPoint point = hashToGeoPoint(hash);
                    long hashAsLong2 = longEncode(point.lon(), point.lat(), p);
                    assertEquals(hash, hashAsLong2);

                    // Same point should be generated from the string key
                    assertEquals(point, hashToGeoPoint(stringEncode(hash)));
                }
            }
        }
    }
}
