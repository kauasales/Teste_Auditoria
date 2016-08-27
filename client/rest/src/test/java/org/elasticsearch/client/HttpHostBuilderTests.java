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
package org.elasticsearch.client;

import org.apache.http.HttpHost;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests {@link HttpHostBuilder}.
 */
public class HttpHostBuilderTests extends RestClientTestCase {

    private final Scheme scheme = randomFrom(Scheme.values());
    private final String hostname = randomAsciiOfLengthBetween(1, 20);
    private final int port = randomIntBetween(1, 65535);

    public void testBuilder() {
        assertHttpHost(HttpHostBuilder.builder(hostname), Scheme.HTTP, hostname, 9200);
        assertHttpHost(HttpHostBuilder.builder(scheme.toString() + "://" + hostname), scheme, hostname, 9200);
        assertHttpHost(HttpHostBuilder.builder(scheme.toString() + "://" + hostname + ":" + port), scheme, hostname, port);
        // weird port, but I don't expect it to explode
        assertHttpHost(HttpHostBuilder.builder(scheme.toString() + "://" + hostname + ":-1"), scheme, hostname, 9200);
        // port without scheme
        assertHttpHost(HttpHostBuilder.builder(hostname + ":" + port), Scheme.HTTP, hostname, port);

        // fairly ordinary
        assertHttpHost(HttpHostBuilder.builder("localhost"), Scheme.HTTP, "localhost", 9200);
        assertHttpHost(HttpHostBuilder.builder("localhost:9200"), Scheme.HTTP, "localhost", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://localhost"), Scheme.HTTP, "localhost", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://localhost:9200"), Scheme.HTTP, "localhost", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://localhost:9200"), Scheme.HTTPS, "localhost", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://boaz-air.local:9200"), Scheme.HTTPS, "boaz-air.local", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://server-dash:19200"), Scheme.HTTPS, "server-dash", 19200);
        assertHttpHost(HttpHostBuilder.builder("server-dash:19200"), Scheme.HTTP, "server-dash", 19200);
        assertHttpHost(HttpHostBuilder.builder("server-dash"), Scheme.HTTP, "server-dash", 9200);
        assertHttpHost(HttpHostBuilder.builder("sub.domain"), Scheme.HTTP, "sub.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://sub.domain"), Scheme.HTTP, "sub.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://sub.domain:9200"), Scheme.HTTP, "sub.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://sub.domain:9200"), Scheme.HTTPS, "sub.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://sub.domain:19200"), Scheme.HTTPS, "sub.domain", 19200);

        // ipv4
        assertHttpHost(HttpHostBuilder.builder("127.0.0.1"), Scheme.HTTP, "127.0.0.1", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://127.0.0.1"), Scheme.HTTP, "127.0.0.1", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://127.0.0.1:9200"), Scheme.HTTP, "127.0.0.1", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://127.0.0.1:9200"), Scheme.HTTPS, "127.0.0.1", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://127.0.0.1:19200"), Scheme.HTTPS, "127.0.0.1", 19200);

        // ipv6
        assertHttpHost(HttpHostBuilder.builder("[::1]"), Scheme.HTTP, "[::1]", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://[::1]"), Scheme.HTTP, "[::1]", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://[::1]:9200"), Scheme.HTTP, "[::1]", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://[::1]:9200"), Scheme.HTTPS, "[::1]", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://[::1]:19200"), Scheme.HTTPS, "[::1]", 19200);
        assertHttpHost(HttpHostBuilder.builder("[fdda:5cc1:23:4::1f]"), Scheme.HTTP, "[fdda:5cc1:23:4::1f]", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://[fdda:5cc1:23:4::1f]"), Scheme.HTTP, "[fdda:5cc1:23:4::1f]", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://[fdda:5cc1:23:4::1f]:9200"), Scheme.HTTP, "[fdda:5cc1:23:4::1f]", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://[fdda:5cc1:23:4::1f]:9200"), Scheme.HTTPS, "[fdda:5cc1:23:4::1f]", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://[fdda:5cc1:23:4::1f]:19200"), Scheme.HTTPS, "[fdda:5cc1:23:4::1f]", 19200);

        // underscores
        assertHttpHost(HttpHostBuilder.builder("server_with_underscore"), Scheme.HTTP, "server_with_underscore", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://server_with_underscore"), Scheme.HTTP, "server_with_underscore", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://server_with_underscore:9200"), Scheme.HTTP, "server_with_underscore", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://server_with_underscore:19200"), Scheme.HTTP, "server_with_underscore", 19200);
        assertHttpHost(HttpHostBuilder.builder("https://server_with_underscore"), Scheme.HTTPS, "server_with_underscore", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://server_with_underscore:9200"), Scheme.HTTPS, "server_with_underscore", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://server_with_underscore:19200"), Scheme.HTTPS, "server_with_underscore", 19200);
        assertHttpHost(HttpHostBuilder.builder("_prefix.domain"), Scheme.HTTP, "_prefix.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://_prefix.domain"), Scheme.HTTP, "_prefix.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://_prefix.domain:9200"), Scheme.HTTP, "_prefix.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("http://_prefix.domain:19200"), Scheme.HTTP, "_prefix.domain", 19200);
        assertHttpHost(HttpHostBuilder.builder("https://_prefix.domain"), Scheme.HTTPS, "_prefix.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://_prefix.domain:9200"), Scheme.HTTPS, "_prefix.domain", 9200);
        assertHttpHost(HttpHostBuilder.builder("https://_prefix.domain:19200"), Scheme.HTTPS, "_prefix.domain", 19200);
    }

    public void testManualBuilder() {
        assertHttpHost(HttpHostBuilder.builder().host(hostname), Scheme.HTTP, hostname, 9200);
        assertHttpHost(HttpHostBuilder.builder().scheme(scheme).host(hostname), scheme, hostname, 9200);
        assertHttpHost(HttpHostBuilder.builder().scheme(scheme).host(hostname).port(port), scheme, hostname, port);
        // unset the port (not normal, but ensuring it works)
        assertHttpHost(HttpHostBuilder.builder().scheme(scheme).host(hostname).port(port).port(-1), scheme, hostname, 9200);
        // port without scheme
        assertHttpHost(HttpHostBuilder.builder().host(hostname).port(port), Scheme.HTTP, hostname, port);
    }

    public void testBuilderNullUri() {
        try {
            HttpHostBuilder.builder(null);
            fail("null uri should fail");
        } catch (final NullPointerException e) {
            assertThat(e.getMessage(), equalTo("uri must not be null"));
        }
    }

    public void testUnknownScheme() {
        assertBuilderBadSchemeThrows("htp://localhost:9200", "htp");
        assertBuilderBadSchemeThrows("htttp://localhost:9200", "htttp");
        assertBuilderBadSchemeThrows("httpd://localhost:9200", "httpd");
        assertBuilderBadSchemeThrows("ws://localhost:9200", "ws");
        assertBuilderBadSchemeThrows("wss://localhost:9200", "wss");
        assertBuilderBadSchemeThrows("ftp://localhost:9200", "ftp");
        assertBuilderBadSchemeThrows("gopher://localhost:9200", "gopher");
        assertBuilderBadSchemeThrows("localhost://9200", "localhost");
    }

    public void testPathIsBlocked() {
        assertBuilderPathThrows("http://localhost:9200/", "/");
        assertBuilderPathThrows("http://localhost:9200/sub", "/sub");
        assertBuilderPathThrows("http://localhost:9200/sub/path", "/sub/path");
    }

    public void testBuildWithoutHost() {
        try {
            HttpHostBuilder.builder().build();
            fail("host should be required");
        } catch (final IllegalStateException e) {
            assertThat(e.getMessage(), equalTo("host must be set"));
        }
    }

    public void testNullScheme() {
        try {
            HttpHostBuilder.builder().scheme(null);
            fail("null scheme is malformed");
        } catch (NullPointerException e) {
            // success
        }
    }

    public void testNullHost() {
        try {
            HttpHostBuilder.builder().host(null);
            fail("null host is malformed");
        } catch (NullPointerException e) {
            // success
        }
    }

    public void testBadPort() {
        assertPortThrows(0);
        assertPortThrows(65536);

        assertPortThrows(randomIntBetween(Integer.MIN_VALUE, -2));
        assertPortThrows(randomIntBetween(65537, Integer.MAX_VALUE));
    }

    private void assertHttpHost(final HttpHostBuilder host, final Scheme scheme, final String hostname, final int port) {
        assertHttpHost(host.build(), scheme, hostname, port);
    }

    private void assertHttpHost(final HttpHost host, final Scheme scheme, final String hostname, final int port) {
        assertThat(host.getSchemeName(), equalTo(scheme.toString()));
        assertThat(host.getHostName(), equalTo(hostname));
        assertThat(host.getPort(), equalTo(port));
    }

    private void assertBuilderPathThrows(final String uri, final String path) {
        try {
            HttpHostBuilder.builder(uri);
            fail("path [" + path + "] should be explicitly ignored");
        } catch (final IllegalArgumentException e) {
            assertThat(e.getMessage(), containsString("[" + path + "]"));
        }
    }

    private void assertBuilderBadSchemeThrows(final String uri, final String scheme) {
        try {
            HttpHostBuilder.builder(uri);
            fail("scheme [" + scheme + "] should be unrecognized");
        } catch (final IllegalArgumentException e) {
            assertThat(e.getMessage(), containsString(scheme));
        }
    }

    private void assertPortThrows(final int port) {
        try {
            HttpHostBuilder.builder().port(port);
            fail("port should be invalid");
        } catch (final IllegalArgumentException e) {
            assertThat(e.getMessage(), containsString(Integer.toString(port)));
        }
    }

}
