/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.script.field;

import org.elasticsearch.common.util.Maps;
import org.elasticsearch.test.ESTestCase;

import java.util.HashMap;
import java.util.Map;

public class MapBackedMetadataTests extends ESTestCase {
    public void testString() {
        MapBackedMetadata m = singleElementMetadata();
        String key = "myKey";
        String value = "myValue";
        assertNull(m.getString(key));
        assertNull(m.getMap().get(key));

        m.set(key, value);
        assertEquals(value, m.getString(key));
        assertEquals(value, m.getMap().get(key));

        m.set(key, 1);
        assertEquals("1", m.getString(key));
        assertEquals(1, m.getMap().get(key));

        m.set(key, null);
        assertNull(m.getString(key));
        assertNull(m.getMap().get(key));

        m.set(key, value);
        assertEquals(value, m.getString(key));
        assertEquals(value, m.getMap().get(key));

        m.getMap().remove(key);
        assertNull(m.getString(key));
        assertNull(m.getMap().get(key));
    }

    public void testIndex() {
        String index = "myIndex";
        MapBackedMetadata m = singleElementMetadata();
        assertNull(m.getIndex());
        assertNull(m.getMap().get("_index"));

        m.setIndex(index);
        assertEquals(index, m.getIndex());
        assertEquals(index, m.getMap().get("_index"));
    }

    public void testId() {
        String id = "myId";
        MapBackedMetadata m = singleElementMetadata();
        assertNull(m.getId());
        assertNull(m.getMap().get("_id"));

        m.setId(id);
        assertEquals(id, m.getId());
        assertEquals(id, m.getMap().get("_id"));
    }

    public void testRouting() {
        String routing = "myRouting";
        MapBackedMetadata m = singleElementMetadata();
        assertNull(m.getRouting());
        assertNull(m.getMap().get("_routing"));

        m.setRouting(routing);
        assertEquals(routing, m.getRouting());
        assertEquals(routing, m.getMap().get("_routing"));
    }

    public void testVersion() {
        long version = 500;
        MapBackedMetadata m = singleElementMetadata();
        assertNull(m.getVersion());
        assertNull(m.getMap().get("_version"));

        m.setVersion(version);
        assertEquals(Long.valueOf(version), m.getVersion());
        assertEquals(version, m.getRawVersion());
        assertEquals(version, m.getMap().get("_version"));

        String badVersion = "badVersion";
        m.set("_version", badVersion);
        assertEquals(badVersion, m.getRawVersion());
        IllegalArgumentException err = expectThrows(IllegalArgumentException.class, m::getVersion);
        assertEquals("version may only be set to an int or a long but was [badVersion] with type [java.lang.String]", err.getMessage());

        double tooBig = Double.MAX_VALUE;
        m.set("_version", tooBig);
        assertEquals(tooBig, m.getRawVersion());
        err = expectThrows(IllegalArgumentException.class, m::getVersion);
        assertEquals("version may only be set to an int or a long but was [" + tooBig + "] with type [java.lang.Double]", err.getMessage());

        long justRight = (long) 1 << 52;
        m.set("_version", (double) justRight);
        assertEquals(Long.valueOf(justRight), m.getVersion());
        assertEquals((double) justRight, m.getRawVersion());
    }

    public void testSource() {
        MapBackedMetadata m = singleElementMetadata();
        Map<String, Object> source = new HashMap<>();
        source.put("foo", "bar");

        m.setSource(source);
        assertEquals(source, m.getSource());
        assertEquals(source, m.getMap().get("_source"));

        source.put("baz", "qux");
        assertEquals("qux", m.getSource().get("baz"));

        m.getMap().put("_source", "mySource");

        IllegalArgumentException err = expectThrows(IllegalArgumentException.class, m::getSource);
        assertEquals("source should be a map, not [mySource] with [java.lang.String]", err.getMessage());
    }

    public void testCtx() {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("_index", "myIndex");
        ctx.put("_id", "myId");
        ctx.put("_version", 200);
        ctx.put("_routing", "myRouting");
        Map<String, Object> source = new HashMap<>();
        source.put("foo", "bar");
        ctx.put("_source", source);

        MapBackedMetadata m = new MapBackedMetadata(ctx);
        assertEquals("myIndex", m.getIndex());
        assertEquals("myId", m.getId());
        assertEquals(Long.valueOf(200), m.getVersion());
        assertEquals("myRouting", m.getRouting());
        assertEquals("bar", m.getSource().get("foo"));
    }

    private MapBackedMetadata singleElementMetadata() {
        return new MapBackedMetadata(Maps.newMapWithExpectedSize(1));
    }
}
