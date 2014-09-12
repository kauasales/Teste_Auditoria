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

package org.elasticsearch.common.path;

import org.elasticsearch.test.ElasticsearchTestCase;
import org.junit.Test;

import java.util.Map;

import static com.google.common.collect.Maps.newHashMap;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

/**
 *
 */
public class PathTrieTests extends ElasticsearchTestCase {

    @Test
    public void testPath() {
        PathTrie<String> trie = new PathTrie<>();
        trie.insert("/a/b/c", "walla");
        trie.insert("a/d/g", "kuku");
        trie.insert("x/b/c", "lala");
        trie.insert("a/x/*", "one");
        trie.insert("a/b/*", "two");
        trie.insert("*/*/x", "three");
        trie.insert("{index}/insert/{docId}", "bingo");

        assertThat(trie.retrieve("a/b/c"), equalTo("walla"));
        assertThat(trie.retrieve("a/d/g"), equalTo("kuku"));
        assertThat(trie.retrieve("x/b/c"), equalTo("lala"));
        assertThat(trie.retrieve("a/x/b"), equalTo("one"));
        assertThat(trie.retrieve("a/b/d"), equalTo("two"));

        assertThat(trie.retrieve("a/b"), nullValue());
        assertThat(trie.retrieve("a/b/c/d"), nullValue());
        assertThat(trie.retrieve("g/t/x"), equalTo("three"));

        Map<String, String> params = newHashMap();
        assertThat(trie.retrieve("index1/insert/12", params), equalTo("bingo"));
        assertThat(params.size(), equalTo(2));
        assertThat(params.get("index"), equalTo("index1"));
        assertThat(params.get("docId"), equalTo("12"));
    }

    @Test
    public void testEmptyPath() {
        PathTrie<String> trie = new PathTrie<>();
        trie.insert("/", "walla");
        assertThat(trie.retrieve(""), equalTo("walla"));
    }

    @Test
    public void testDifferentNamesOnDifferentPath() {
        PathTrie<String> trie = new PathTrie<>();
        trie.insert("/a/{type}", "test1");
        trie.insert("/b/{name}", "test2");

        Map<String, String> params = newHashMap();
        assertThat(trie.retrieve("/a/test", params), equalTo("test1"));
        assertThat(params.get("type"), equalTo("test"));

        params.clear();
        assertThat(trie.retrieve("/b/testX", params), equalTo("test2"));
        assertThat(params.get("name"), equalTo("testX"));
    }

    @Test
    public void testSameNameOnDifferentPath() {
        PathTrie<String> trie = new PathTrie<>();
        trie.insert("/a/c/{name}", "test1");
        trie.insert("/b/{name}", "test2");

        Map<String, String> params = newHashMap();
        assertThat(trie.retrieve("/a/c/test", params), equalTo("test1"));
        assertThat(params.get("name"), equalTo("test"));

        params.clear();
        assertThat(trie.retrieve("/b/testX", params), equalTo("test2"));
        assertThat(params.get("name"), equalTo("testX"));
    }

    @Test
    public void testPreferNonWildcardExecution() {
        PathTrie<String> trie = new PathTrie<>();
        trie.insert("{test}", "test1");
        trie.insert("b", "test2");
        trie.insert("{test}/a", "test3");
        trie.insert("b/a", "test4");
        trie.insert("{test}/{testB}", "test5");
        trie.insert("{test}/x/{testC}", "test6");

        Map<String, String> params = newHashMap();
        assertThat(trie.retrieve("/b", params), equalTo("test2"));
        assertThat(trie.retrieve("/b/a", params), equalTo("test4"));
        assertThat(trie.retrieve("/v/x", params), equalTo("test5"));
        assertThat(trie.retrieve("/v/x/c", params), equalTo("test6"));
    }

    @Test
    public void testSamePathConcreteResolution() {
        PathTrie<String> trie = new PathTrie<>();
        trie.insert("{x}/{y}/{z}", "test1");
        trie.insert("{x}/_y/{k}", "test2");

        Map<String, String> params = newHashMap();
        assertThat(trie.retrieve("/a/b/c", params), equalTo("test1"));
        assertThat(params.get("x"), equalTo("a"));
        assertThat(params.get("y"), equalTo("b"));
        assertThat(params.get("z"), equalTo("c"));
        params.clear();
        assertThat(trie.retrieve("/a/_y/c", params), equalTo("test2"));
        assertThat(params.get("x"), equalTo("a"));
        assertThat(params.get("k"), equalTo("c"));
    }

    @Test
    public void testNamedWildcardAndLookupWithWildcard() {
        PathTrie<String> trie = new PathTrie<>();
        trie.insert("x/{test}", "test1");
        trie.insert("{test}/a", "test2");
        trie.insert("/{test}", "test3");
        trie.insert("/{test}/_endpoint", "test4");
        trie.insert("/*/{test}/_endpoint", "test5");

        Map<String, String> params = newHashMap();
        assertThat(trie.retrieve("/x/*", params), equalTo("test1"));
        assertThat(params.get("test"), equalTo("*"));

        params = newHashMap();
        assertThat(trie.retrieve("/b/a", params), equalTo("test2"));
        assertThat(params.get("test"), equalTo("b"));

        params = newHashMap();
        assertThat(trie.retrieve("/*", params), equalTo("test3"));
        assertThat(params.get("test"), equalTo("*"));

        params = newHashMap();
        assertThat(trie.retrieve("/*/_endpoint", params), equalTo("test4"));
        assertThat(params.get("test"), equalTo("*"));

        params = newHashMap();
        assertThat(trie.retrieve("a/*/_endpoint", params), equalTo("test5"));
        assertThat(params.get("test"), equalTo("*"));
    }
}
