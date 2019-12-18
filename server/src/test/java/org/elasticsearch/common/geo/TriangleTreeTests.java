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
package org.elasticsearch.common.geo;

import org.elasticsearch.geo.GeometryTestUtils;
import org.elasticsearch.geometry.Geometry;
import org.elasticsearch.geometry.GeometryCollection;
import org.elasticsearch.geometry.Line;
import org.elasticsearch.geometry.LinearRing;
import org.elasticsearch.geometry.MultiLine;
import org.elasticsearch.geometry.MultiPoint;
import org.elasticsearch.geometry.Point;
import org.elasticsearch.geometry.Polygon;
import org.elasticsearch.geometry.Rectangle;
import org.elasticsearch.index.mapper.GeoShapeIndexer;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import static org.elasticsearch.common.geo.GeoTestUtils.assertRelation;
import static org.elasticsearch.common.geo.GeoTestUtils.triangleTreeReader;
import static org.elasticsearch.geo.GeometryTestUtils.fold;
import static org.elasticsearch.geo.GeometryTestUtils.randomLine;
import static org.elasticsearch.geo.GeometryTestUtils.randomMultiLine;
import static org.elasticsearch.geo.GeometryTestUtils.randomMultiPoint;
import static org.elasticsearch.geo.GeometryTestUtils.randomMultiPolygon;
import static org.elasticsearch.geo.GeometryTestUtils.randomPoint;
import static org.elasticsearch.geo.GeometryTestUtils.randomPolygon;
import static org.elasticsearch.geo.GeometryTestUtils.randomRectangle;
import static org.hamcrest.Matchers.equalTo;

public class TriangleTreeTests extends ESTestCase {

    @SuppressWarnings("unchecked")
    public void testDimensionalShapeType() throws IOException {
        assertDimensionalShapeType(randomPoint(false), DimensionalShapeType.POINT);
        assertDimensionalShapeType(randomMultiPoint(false), DimensionalShapeType.MULTIPOINT);
        assertDimensionalShapeType(randomLine(false), DimensionalShapeType.LINESTRING);
        assertDimensionalShapeType(randomMultiLine(false), DimensionalShapeType.MULTILINESTRING);
        assertDimensionalShapeType(randomPolygon(false), DimensionalShapeType.POLYGON);
        assertDimensionalShapeType(randomMultiPolygon(false), DimensionalShapeType.MULTIPOLYGON);
        assertDimensionalShapeType(randomRectangle(), DimensionalShapeType.POLYGON);
        assertDimensionalShapeType(randomFrom(
            new GeometryCollection<>(List.of(randomPoint(false))),
            new GeometryCollection<>(List.of(randomMultiPoint(false))),
            new GeometryCollection<>(Collections.singletonList(
                new GeometryCollection<>(List.of(randomPoint(false), randomMultiPoint(false))))))
            , DimensionalShapeType.GEOMETRYCOLLECTION_POINTS);
        assertDimensionalShapeType(randomFrom(
            new GeometryCollection<>(List.of(randomPoint(false), randomLine(false))),
            new GeometryCollection<>(List.of(randomMultiPoint(false), randomMultiLine(false))),
            new GeometryCollection<>(Collections.singletonList(
                new GeometryCollection<>(List.of(randomPoint(false), randomLine(false))))))
            , DimensionalShapeType.GEOMETRYCOLLECTION_LINES);
        assertDimensionalShapeType(randomFrom(
            new GeometryCollection<>(List.of(randomPoint(false), randomLine(false), randomPolygon(false))),
            new GeometryCollection<>(List.of(randomMultiPoint(false), randomMultiPolygon(false))),
            new GeometryCollection<>(Collections.singletonList(
                new GeometryCollection<>(List.of(randomLine(false), randomPolygon(false))))))
            , DimensionalShapeType.GEOMETRYCOLLECTION_POLYGONS);
    }


    public void testRectangleShape() throws IOException {
        for (int i = 0; i < 1000; i++) {
            int minX = randomIntBetween(-40, -1);
            int maxX = randomIntBetween(1, 40);
            int minY = randomIntBetween(-40, -1);
            int maxY = randomIntBetween(1, 40);
            double[] x = new double[]{minX, maxX, maxX, minX, minX};
            double[] y = new double[]{minY, minY, maxY, maxY, minY};
            Geometry rectangle = new Rectangle(minX, maxX, maxY, minY);
            TriangleTreeReader reader = triangleTreeReader(rectangle, GeoShapeCoordinateEncoder.INSTANCE);

            Extent expectedExtent  = getExtentFromBox(minX, minY, maxX, maxY);
            assertThat(expectedExtent, equalTo(reader.getExtent()));
            // centroid is calculated using original double values but then loses precision as it is serialized as an integer
            int encodedCentroidX = GeoShapeCoordinateEncoder.INSTANCE.encodeX(((double) minX + maxX) / 2);
            int encodedCentroidY = GeoShapeCoordinateEncoder.INSTANCE.encodeY(((double) minY + maxY) / 2);
            assertEquals(GeoShapeCoordinateEncoder.INSTANCE.decodeX(encodedCentroidX), reader.getWeightedCentroidX(), 0.0000001);
            assertEquals(GeoShapeCoordinateEncoder.INSTANCE.decodeY(encodedCentroidY), reader.getWeightedCentroidY(), 0.0000001);

            // box-query touches bottom-left corner
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(minX - randomIntBetween(1, 180 + minX),
                minY - randomIntBetween(1, 90 + minY), minX, minY));
            // box-query touches bottom-right corner
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(maxX, minY - randomIntBetween(1, 90 + minY),
                maxX + randomIntBetween(1, 180 - maxX), minY));
            // box-query touches top-right corner
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(maxX, maxY, maxX + randomIntBetween(1, 180 - maxX),
                maxY + randomIntBetween(1, 90 - maxY)));
            // box-query touches top-left corner
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(minX - randomIntBetween(1, 180 + minX), maxY, minX,
                maxY + randomIntBetween(1, 90 - maxY)));
            // box-query fully-enclosed inside rectangle
            assertRelation(GeoRelation.QUERY_INSIDE, reader, getExtentFromBox(3 * (minX + maxX) / 4, 3 * (minY + maxY) / 4,
                3 * (maxX + minX) / 4, 3 * (maxY + minY) / 4));
            // box-query fully-contains poly
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(minX - randomIntBetween(1, 180 + minX),
                minY - randomIntBetween(1, 90 + minY), maxX + randomIntBetween(1, 180 - maxX),
                maxY + randomIntBetween(1, 90 - maxY)));
            // box-query half-in-half-out-right
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(3 * (minX + maxX) / 4, 3 * (minY + maxY) / 4,
                maxX + randomIntBetween(1, 90 - maxY), 3 * (maxY + minY) / 4));
            // box-query half-in-half-out-left
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(minX - randomIntBetween(1, 180 + minX),
                3 * (minY + maxY) / 4, 3 * (maxX + minX) / 4, 3 * (maxY + minY) / 4));
            // box-query half-in-half-out-top
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(3 * (minX + maxX) / 4, 3 * (minY + maxY) / 4,
                maxX + randomIntBetween(1, 180 - maxX), maxY + randomIntBetween(1, 90 - maxY)));
            // box-query half-in-half-out-bottom
            assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(3 * (minX + maxX) / 4,
                minY - randomIntBetween(1, 90 + minY), maxX + randomIntBetween(1, 180 - maxX),
                3 * (maxY + minY) / 4));

            // box-query outside to the right
            assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(maxX + randomIntBetween(1, 180 - maxX), minY,
                maxX + randomIntBetween(1, 180 - maxX), maxY));
            // box-query outside to the left
            assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(maxX - randomIntBetween(1, 180 - maxX), minY,
                minX - randomIntBetween(1, 180 + minX), maxY));
            // box-query outside to the top
            assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(minX, maxY + randomIntBetween(1, 90 - maxY), maxX,
                maxY + randomIntBetween(1, 90 - maxY)));
            // box-query outside to the bottom
            assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(minX, minY - randomIntBetween(1, 90 + minY), maxX,
                minY - randomIntBetween(1, 90 + minY)));
        }
    }

    public void testPacManPolygon() throws Exception {
        // pacman
        double[] px = {0, 10, 10, 0, -8, -10, -8, 0, 10, 10, 0};
        double[] py = {0, 5, 9, 10, 9, 0, -9, -10, -9, -5, 0};

        // test cell crossing poly
        TriangleTreeReader reader = triangleTreeReader(new Polygon(new LinearRing(py, px), Collections.emptyList()),
            TestCoordinateEncoder.INSTANCE);
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(2, -1, 11, 1));
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(-12, -12, 12, 12));
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(-2, -1, 2, 0));
        assertRelation(GeoRelation.QUERY_INSIDE, reader, getExtentFromBox(-5, -6, 2, -2));
    }

    // adapted from org.apache.lucene.geo.TestPolygon2D#testMultiPolygon
    public void testPolygonWithHole() throws Exception {
        Polygon polyWithHole = new Polygon(new LinearRing(new double[]{-50, 50, 50, -50, -50}, new double[]{-50, -50, 50, 50, -50}),
            Collections.singletonList(new LinearRing(new double[]{-10, 10, 10, -10, -10}, new double[]{-10, -10, 10, 10, -10})));

        TriangleTreeReader reader = triangleTreeReader(polyWithHole, GeoShapeCoordinateEncoder.INSTANCE);

        assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(6, -6, 6, -6)); // in the hole
        assertRelation(GeoRelation.QUERY_INSIDE, reader, getExtentFromBox(25, -25, 25, -25)); // on the mainland
        assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(51, 51, 52, 52)); // outside of mainland
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(-60, -60, 60, 60)); // enclosing us completely
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(49, 49, 51, 51)); // overlapping the mainland
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(9, 9, 11, 11)); // overlapping the hole
    }

    public void testCombPolygon() throws Exception {
        double[] px = {0, 10, 10, 20, 20, 30, 30, 40, 40, 50, 50, 0, 0};
        double[] py = {0, 0, 20, 20, 0, 0, 20, 20, 0, 0, 30, 30, 0};

        double[] hx = {21, 21, 29, 29, 21};
        double[] hy = {1, 20, 20, 1, 1};

        Polygon polyWithHole = new Polygon(new LinearRing(px, py), Collections.singletonList(new LinearRing(hx, hy)));
        TriangleTreeReader reader = triangleTreeReader(polyWithHole, GeoShapeCoordinateEncoder.INSTANCE);
        // test cell crossing poly
        assertRelation(GeoRelation.QUERY_INSIDE, reader, getExtentFromBox(5, 10, 5, 10));
        assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(15, 10, 15, 10));
        assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(25, 10, 25, 10));
    }

    public void testPacManClosedLineString() throws Exception {
        // pacman
        double[] px = {0, 10, 10, 0, -8, -10, -8, 0, 10, 10, 0};
        double[] py = {0, 5, 9, 10, 9, 0, -9, -10, -9, -5, 0};

        // test cell crossing poly
        TriangleTreeReader reader = triangleTreeReader(new Line(px, py), GeoShapeCoordinateEncoder.INSTANCE);
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(2, -1, 11, 1));
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(-12, -12, 12, 12));
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(-2, -1, 2, 0));
        assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(-5, -6, 2, -2));
    }

    public void testPacManLineString() throws Exception {
        // pacman
        double[] px = {0, 10, 10, 0, -8, -10, -8, 0, 10, 10};
        double[] py = {0, 5, 9, 10, 9, 0, -9, -10, -9, -5};

        // test cell crossing poly
        TriangleTreeReader reader = triangleTreeReader(new Line(px, py), GeoShapeCoordinateEncoder.INSTANCE);
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(2, -1, 11, 1));
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(-12, -12, 12, 12));
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(-2, -1, 2, 0));
        assertRelation(GeoRelation.QUERY_DISJOINT, reader, getExtentFromBox(-5, -6, 2, -2));
    }

    public void testPacManPoints() throws Exception {
        // pacman
        List<Point> points = Arrays.asList(
            new Point(0, 0),
            new Point(5, 10),
            new Point(9, 10),
            new Point(10, 0),
            new Point(9, -8),
            new Point(0, -10),
            new Point(-9, -8),
            new Point(-10, 0),
            new Point(-9, 10),
            new Point(-5, 10)
        );


        // candidate intersects cell
        int xMin = 0;
        int xMax = 11;
        int yMin = -10;
        int yMax = 9;

        // test cell crossing poly
        TriangleTreeReader reader = triangleTreeReader(new MultiPoint(points), GeoShapeCoordinateEncoder.INSTANCE);
        assertRelation(GeoRelation.QUERY_CROSSES, reader, getExtentFromBox(xMin, yMin, xMax, yMax));
    }

    public void testRandomMultiLineIntersections() throws IOException {
        double extentSize = randomDoubleBetween(0.01, 10, true);
        GeoShapeIndexer indexer = new GeoShapeIndexer(true, "test");
        MultiLine geometry = randomMultiLine(false);
        geometry = (MultiLine) indexer.prepareForIndexing(geometry);

        TriangleTreeReader reader = triangleTreeReader(geometry, GeoShapeCoordinateEncoder.INSTANCE);
        Extent readerExtent = reader.getExtent();

        for (Line line : geometry) {
            // extent that intersects edges
            assertRelation(GeoRelation.QUERY_CROSSES, reader, bufferedExtentFromGeoPoint(line.getX(0), line.getY(0), extentSize));

            // extent that fully encloses a line in the MultiLine
            Extent lineExtent = triangleTreeReader(line, GeoShapeCoordinateEncoder.INSTANCE).getExtent();
            assertRelation(GeoRelation.QUERY_CROSSES, reader, lineExtent);

            if (lineExtent.minX() != Integer.MIN_VALUE && lineExtent.maxX() != Integer.MAX_VALUE
                && lineExtent.minY() != Integer.MIN_VALUE && lineExtent.maxY() != Integer.MAX_VALUE) {
                assertRelation(GeoRelation.QUERY_CROSSES, reader, Extent.fromPoints(lineExtent.minX() - 1, lineExtent.minY() - 1,
                    lineExtent.maxX() + 1, lineExtent.maxY() + 1));
            }
        }

        // extent that fully encloses the MultiLine
        assertRelation(GeoRelation.QUERY_CROSSES, reader, reader.getExtent());
        if (readerExtent.minX() != Integer.MIN_VALUE && readerExtent.maxX() != Integer.MAX_VALUE
            && readerExtent.minY() != Integer.MIN_VALUE && readerExtent.maxY() != Integer.MAX_VALUE) {
            assertRelation(GeoRelation.QUERY_CROSSES, reader, Extent.fromPoints(readerExtent.minX() - 1, readerExtent.minY() - 1,
                readerExtent.maxX() + 1, readerExtent.maxY() + 1));
        }

    }

    public void testRandomGeometryIntersection() throws IOException {
        int testPointCount = randomIntBetween(100, 200);
        Point[] testPoints = new Point[testPointCount];
        double extentSize = randomDoubleBetween(1, 10, true);
        boolean[] intersects = new boolean[testPointCount];
        for (int i = 0; i < testPoints.length; i++) {
            testPoints[i] = randomPoint(false);
        }

        Geometry geometry = randomGeometryTreeGeometry();
        GeoShapeIndexer indexer = new GeoShapeIndexer(true, "test");
        Geometry preparedGeometry = indexer.prepareForIndexing(geometry);

        for (int i = 0; i < testPointCount; i++) {
            int cur = i;
            intersects[cur] = fold(preparedGeometry, false, (g, s) -> s || intersects(g, testPoints[cur], extentSize));
        }

        for (int i = 0; i < testPointCount; i++) {
            assertEquals(intersects[i], intersects(preparedGeometry, testPoints[i], extentSize));
        }
    }

    private Extent bufferedExtentFromGeoPoint(double x, double y, double extentSize) {
        int xMin = GeoShapeCoordinateEncoder.INSTANCE.encodeX(Math.max(x - extentSize, -180.0));
        int xMax = GeoShapeCoordinateEncoder.INSTANCE.encodeX(Math.min(x + extentSize, 180.0));
        int yMin = GeoShapeCoordinateEncoder.INSTANCE.encodeY(Math.max(y - extentSize, -90));
        int yMax = GeoShapeCoordinateEncoder.INSTANCE.encodeY(Math.min(y + extentSize, 90));
        return Extent.fromPoints(xMin, yMin, xMax, yMax);
    }

    private static Extent getExtentFromBox(double bottomLeftX, double bottomLeftY, double topRightX, double topRightY) {
        return Extent.fromPoints(GeoShapeCoordinateEncoder.INSTANCE.encodeX(bottomLeftX),
            GeoShapeCoordinateEncoder.INSTANCE.encodeY(bottomLeftY),
            GeoShapeCoordinateEncoder.INSTANCE.encodeX(topRightX),
            GeoShapeCoordinateEncoder.INSTANCE.encodeY(topRightY));

    }

    private boolean intersects(Geometry g, Point p, double extentSize) throws IOException {

        Extent bufferBounds = bufferedExtentFromGeoPoint(p.getX(), p.getY(), extentSize);
        GeoRelation relation = triangleTreeReader(g, GeoShapeCoordinateEncoder.INSTANCE)
            .relate(bufferBounds.minX(), bufferBounds.minY(), bufferBounds.maxX(), bufferBounds.maxY());
        return relation == GeoRelation.QUERY_CROSSES || relation == GeoRelation.QUERY_INSIDE;
    }

    private static Geometry randomGeometryTreeGeometry() {
        return randomGeometryTreeGeometry(0);
    }

    private static Geometry randomGeometryTreeGeometry(int level) {
        @SuppressWarnings("unchecked") Function<Boolean, Geometry> geometry = ESTestCase.randomFrom(
            GeometryTestUtils::randomLine,
            GeometryTestUtils::randomPoint,
            GeometryTestUtils::randomPolygon,
            GeometryTestUtils::randomMultiLine,
            GeometryTestUtils::randomMultiPoint,
            level < 3 ? (b) -> randomGeometryTreeCollection(level + 1) : GeometryTestUtils::randomPoint // don't build too deep
        );
        return geometry.apply(false);
    }

    private static Geometry randomGeometryTreeCollection(int level) {
        int size = ESTestCase.randomIntBetween(1, 10);
        List<Geometry> shapes = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            shapes.add(randomGeometryTreeGeometry(level));
        }
        return new GeometryCollection<>(shapes);
    }

    private static void assertDimensionalShapeType(Geometry geometry, DimensionalShapeType expected) throws IOException {
        TriangleTreeReader reader = triangleTreeReader(geometry, GeoShapeCoordinateEncoder.INSTANCE);
        assertThat(reader.getDimensionalShapeType(), equalTo(expected));
    }
}
