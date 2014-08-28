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

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.action.indexedscripts.get.GetIndexedScriptRequest;
import org.elasticsearch.action.indexedscripts.put.PutIndexedScriptRequest;
import org.elasticsearch.action.indexedscripts.put.PutIndexedScriptResponse;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.test.ElasticsearchIntegrationTest;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertExists;
import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertHitCount;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

public class IndexedScriptTests extends ElasticsearchIntegrationTest {

    @Test
    public void testFieldIndexedScript()  throws ExecutionException, InterruptedException{
        List<IndexRequestBuilder> builders = new ArrayList();
        builders.add(client().prepareIndex(ScriptService.SCRIPT_INDEX, "groovy", "script1").setSource("{" +
                "\"script\":\"2\""+
        "}").setTimeout(TimeValue.timeValueSeconds(randomIntBetween(2,10))));

        builders.add(client().prepareIndex(ScriptService.SCRIPT_INDEX, "groovy", "script2").setSource("{" +
                "\"script\":\"factor*2\""+
                "}"));

        indexRandom(true, builders);

        builders.clear();

        builders.add(client().prepareIndex("test", "scriptTest", "1").setSource("{\"theField\":\"foo\"}"));
        builders.add(client().prepareIndex("test", "scriptTest", "2").setSource("{\"theField\":\"foo 2\"}"));
        builders.add(client().prepareIndex("test", "scriptTest", "3").setSource("{\"theField\":\"foo 3\"}"));
        builders.add(client().prepareIndex("test", "scriptTest", "4").setSource("{\"theField\":\"foo 4\"}"));
        builders.add(client().prepareIndex("test", "scriptTest", "5").setSource("{\"theField\":\"bar\"}"));

        indexRandom(true,builders);
        SearchResponse searchResponse;
        String query = "{ \"query\" : { \"match_all\": {}} , \"script_fields\" : { \"test1\" : { \"script_id\" : \"script1\", \"lang\":\"groovy\" }, \"test2\" : { \"script_id\" : \"script2\", \"lang\":\"groovy\", \"params\":{\"factor\":3}  }}, size:1}";
        searchResponse = client().prepareSearch().setSource(query).setIndices("test").setTypes("scriptTest").get();
        assertHitCount(searchResponse,5);
        assertTrue(searchResponse.getHits().hits().length == 1);
        SearchHit sh = searchResponse.getHits().getAt(0);
        assertThat((Integer)sh.field("test1").getValue(), equalTo(2));
        assertThat((Integer)sh.field("test2").getValue(), equalTo(6));
    }

    @Test
    public void testThatShortTimeoutFails() throws ExecutionException, InterruptedException {
        PutIndexedScriptRequest putIndexedScriptRequest = new PutIndexedScriptRequest();
        putIndexedScriptRequest.id("foobar");
        putIndexedScriptRequest.scriptLang("groovy");
        putIndexedScriptRequest.source("{" +
                "\"script\":\"factor*2\"" +
                "}");
        PutIndexedScriptResponse putIndexedScriptResponse = client().putIndexedScript(putIndexedScriptRequest).actionGet();
        assertTrue(putIndexedScriptResponse.isCreated());

        GetIndexedScriptRequest getIndexedScriptRequest = new GetIndexedScriptRequest();
        getIndexedScriptRequest.id("foobar");
        getIndexedScriptRequest.scriptLang("groovy");

        TimeValue timeout = new TimeValue(10);
        getIndexedScriptRequest.timeout(timeout);
        long start = System.currentTimeMillis();
        try {
            client().getIndexedScript(getIndexedScriptRequest).actionGet();
        } catch (ElasticsearchTimeoutException timeoutException) {
            return; //This is ok
        }
        long durationInMs = System.currentTimeMillis() - start;
        assertThat(durationInMs, lessThanOrEqualTo(timeout.getMillis()+1000) ); //Give a second leeway perhaps this is too much ?

    }
}
