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
package org.elasticsearch.script;

import org.elasticsearch.ResourceNotFoundException;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.DiffableUtils;
import org.elasticsearch.common.io.stream.InputStreamStreamInput;
import org.elasticsearch.common.io.stream.OutputStreamStreamOutput;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.script.Script.StoredScriptSource;
import org.elasticsearch.test.ESTestCase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


public class ScriptMetaDataTests extends ESTestCase {

    public void testGetScript() throws Exception {
        Map<String, StoredScriptSource> scripts = new HashMap<>();

        scripts.put("template", new StoredScriptSource(true, null, "lang", "value", Collections.emptyMap()));
        scripts.put("template_field", new StoredScriptSource(true, null, "lang", "value", Collections.emptyMap()));
        scripts.put("script", new StoredScriptSource(false, null, "lang", "value", Collections.emptyMap()));
        scripts.put("script_field", new StoredScriptSource(false, null, "lang", "value", Collections.emptyMap()));
        scripts.put("any", new StoredScriptSource(false, null, "lang", "value", Collections.emptyMap()));

        ScriptMetaData scriptMetaData = new ScriptMetaData(scripts);

        assertEquals(new StoredScriptSource(true, null, "lang", "value", Collections.emptyMap()), scriptMetaData.getScript("template"));
        assertEquals("value", scriptMetaData.getScript("template_field").code);
        assertEquals(new StoredScriptSource(false, null, "lang", "value", Collections.emptyMap()), scriptMetaData.getScript("script"));
        assertEquals("value", scriptMetaData.getScript("script_field").code);
        assertEquals(new StoredScriptSource(false, null, "lang", "value", Collections.emptyMap()), scriptMetaData.getScript("any"));
    }

    public void testToAndFromXContent() throws IOException {
        XContentType contentType = randomFrom(XContentType.values());
        XContentBuilder xContentBuilder = XContentBuilder.builder(contentType.xContent());
        ScriptMetaData expected = randomScriptMetaData();

        xContentBuilder.startObject();
        expected.toXContent(xContentBuilder, new ToXContent.MapParams(Collections.emptyMap()));
        xContentBuilder.endObject();
        xContentBuilder = shuffleXContent(xContentBuilder);

        XContentParser parser = XContentHelper.createParser(xContentBuilder.bytes());
        parser.nextToken();
        ScriptMetaData result = ScriptMetaData.PROTO.fromXContent(parser);
        assertEquals(expected, result);
        assertEquals(expected.hashCode(), result.hashCode());
    }

    public void testReadFromWriteTo() throws IOException {
        ScriptMetaData expected = randomScriptMetaData();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        expected.writeTo(new OutputStreamStreamOutput(out));

        ScriptMetaData result = ScriptMetaData.PROTO.readFrom(new InputStreamStreamInput(new ByteArrayInputStream(out.toByteArray())));
        assertEquals(expected, result);
        assertEquals(expected.hashCode(), result.hashCode());
    }

    public void testDiff() throws Exception {
        Map<String, StoredScriptSource> scripts = new HashMap<>();

        scripts.put("1", new StoredScriptSource(false, null, "lang", "abc", Collections.emptyMap()));
        scripts.put("2", new StoredScriptSource(false, null, "lang", "def", Collections.emptyMap()));
        scripts.put("3", new StoredScriptSource(false, null, "lang", "ghi", Collections.emptyMap()));

        ScriptMetaData scriptMetaData1 = new ScriptMetaData(scripts);

        scripts.put("2", new StoredScriptSource(false, null, "lang", "changed", Collections.emptyMap()));
        scripts.remove("3");
        scripts.put("4", new StoredScriptSource(false, null, "lang", "jkl", Collections.emptyMap()));

        ScriptMetaData scriptMetaData2 = new ScriptMetaData(scripts);

        ScriptMetaData.ScriptMetadataDiff diff = (ScriptMetaData.ScriptMetadataDiff) scriptMetaData2.diff(scriptMetaData1);
        assertEquals(1, ((DiffableUtils.MapDiff) diff.pipelines).getDeletes().size());
        assertEquals("3", ((DiffableUtils.MapDiff) diff.pipelines).getDeletes().get(0));
        assertEquals(1, ((DiffableUtils.MapDiff) diff.pipelines).getDiffs().size());
        assertNotNull(((DiffableUtils.MapDiff) diff.pipelines).getDiffs().get("2"));
        assertEquals(1, ((DiffableUtils.MapDiff) diff.pipelines).getUpserts().size());
        assertNotNull(((DiffableUtils.MapDiff) diff.pipelines).getUpserts().get("4"));

        ScriptMetaData result = (ScriptMetaData) diff.apply(scriptMetaData1);
        assertEquals(new StoredScriptSource(false, null, "lang", "abc", Collections.emptyMap()), result.getScript("1"));
        assertEquals(new StoredScriptSource(false, null, "lang", "changed", Collections.emptyMap()), result.getScript("2"));
        assertEquals(new StoredScriptSource(false, null, "lang", "jkl", Collections.emptyMap()), result.getScript("4"));
    }

    public void testStoreScript() throws Exception {
        ClusterState empty = ClusterState.builder(new ClusterName("_name")).build();
        ClusterState result = ScriptMetaData.storeScript(empty, "_id",
            new StoredScriptSource(false, null, "_lang", "abc", Collections.emptyMap()));
        ScriptMetaData scriptMetaData = result.getMetaData().custom(ScriptMetaData.TYPE);
        assertNotNull(scriptMetaData);
        assertEquals("abc", scriptMetaData.getScript("_id").code);
    }

    public void testDeleteScript() throws Exception {
        ClusterState empty = ClusterState.builder(new ClusterName("_name")).build();
        ClusterState store = ScriptMetaData.storeScript(empty, "_id",
            new StoredScriptSource(false, null, "_lang", "abc", Collections.emptyMap()));

        ClusterState delete = ScriptMetaData.deleteScript(store, "_id");
        ScriptMetaData scriptMetaData = delete.getMetaData().custom(ScriptMetaData.TYPE);
        assertNotNull(scriptMetaData);
        assertNull(scriptMetaData.getScript("_id"));

        ResourceNotFoundException e = expectThrows(ResourceNotFoundException.class, () -> {
            ScriptMetaData.deleteScript(delete, "_non_existing_id");
        });
        assertEquals("stored script with id [_non_existing_id] does not exist", e.getMessage());
    }

    public void testGetStoredScript() throws Exception {
        ClusterState empty = ClusterState.builder(new ClusterName("_name")).build();
        ClusterState store = ScriptMetaData.storeScript(empty, "_id",
            new StoredScriptSource(false, null, "_lang", "abc", Collections.emptyMap()));

        assertEquals(new StoredScriptSource(false, null, "_lang", "abc", Collections.emptyMap()), ScriptMetaData.getScript(store, "_id"));
        assertNull(ScriptMetaData.getScript(store, "_id2"));

        store = ClusterState.builder(new ClusterName("_name")).build();
        assertNull(ScriptMetaData.getScript(store, "_id"));
    }

    private ScriptMetaData randomScriptMetaData() throws IOException {
        Map<String, StoredScriptSource> scripts = new HashMap<>();
        int numScripts = scaledRandomIntBetween(0, 32);

        for (int i = 0; i < numScripts; i++) {
            String id = randomAsciiOfLength(i + 1);
            String lang = randomAsciiOfLength(4);
            String code = randomAsciiOfLength(between(10, 30));

            scripts.put(id, new StoredScriptSource(false, null, lang, code, Collections.emptyMap()));
        }

        return new ScriptMetaData(scripts);
    }

}
