/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.smoketest;

import com.carrotsearch.randomizedtesting.annotations.Name;
import org.apache.http.HttpHost;
import org.elasticsearch.Version;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.test.rest.yaml.ClientYamlDocsTestClient;
import org.elasticsearch.test.rest.yaml.ClientYamlTestCandidate;
import org.elasticsearch.test.rest.yaml.ClientYamlTestClient;
import org.elasticsearch.test.rest.yaml.ClientYamlTestResponse;
import org.elasticsearch.test.rest.yaml.restspec.ClientYamlSuiteRestSpec;
import org.elasticsearch.xpack.test.rest.XPackRestIT;
import org.junit.After;

import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;
import static org.hamcrest.Matchers.is;

public class XDocsClientYamlTestSuiteIT extends XPackRestIT {
    private static final String USER_TOKEN = basicAuthHeaderValue("test_admin", new SecureString("x-pack-test-password".toCharArray()));

    public XDocsClientYamlTestSuiteIT(@Name("yaml") ClientYamlTestCandidate testCandidate) {
        super(testCandidate);
    }

    @Override
    protected void afterIfFailed(List<Throwable> errors) {
        super.afterIfFailed(errors);
        String name = getTestName().split("=")[1];
        name = name.substring(0, name.length() - 1);
        name = name.replaceAll("/([^/]+)$", ".asciidoc:$1");
        logger.error("This failing test was generated by documentation starting at {}. It may include many snippets. "
                + "See Elasticsearch's docs/README.asciidoc for an explanation of test generation.", name);
    }

    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    @Override
    protected ClientYamlTestClient initClientYamlTestClient(
            final ClientYamlSuiteRestSpec restSpec,
            final RestClient restClient,
            final List<HttpHost> hosts,
            final Version esVersion,
            final Version masterVersion) {
        return new ClientYamlDocsTestClient(restSpec, restClient, hosts, esVersion, masterVersion, this::getClientBuilderWithSniffedHosts);
    }

    /**
     * All tests run as a an administrative user but use <code>es-shield-runas-user</code> to become a less privileged user.
     */
    @Override
    protected Settings restClientSettings() {
        return Settings.builder()
                .put(ThreadContext.PREFIX + ".Authorization", USER_TOKEN)
                .build();
    }

    /**
     * Re-enables watcher after every test just in case any test disables it. One does.
     */
    @After
    public void reenableWatcher() throws Exception {
        if (isWatcherTest()) {
            assertBusy(() -> {
                ClientYamlTestResponse response =
                        getAdminExecutionContext().callApi("xpack.watcher.stats", emptyMap(), emptyList(), emptyMap());
                String state = (String) response.evaluate("stats.0.watcher_state");

                switch (state) {
                    case "stopped":
                        ClientYamlTestResponse startResponse =
                                getAdminExecutionContext().callApi("xpack.watcher.start", emptyMap(), emptyList(), emptyMap());
                        boolean isAcknowledged = (boolean) startResponse.evaluate("acknowledged");
                        assertThat(isAcknowledged, is(true));
                        break;
                    case "stopping":
                        throw new AssertionError("waiting until stopping state reached stopped state to start again");
                    case "starting":
                        throw new AssertionError("waiting until starting state reached started state");
                    case "started":
                        // all good here, we are done
                        break;
                    default:
                        throw new AssertionError("unknown state[" + state + "]");
                }
            });
        }
    }

    @Override
    protected boolean isWatcherTest() {
        String testName = getTestName();
        return testName != null && (testName.contains("watcher/") || testName.contains("watcher\\"));
    }

    @Override
    protected boolean isMonitoringTest() {
        return false;
    }

    @Override
    protected boolean isMachineLearningTest() {
        String testName = getTestName();
        return testName != null && (testName.contains("ml/") || testName.contains("ml\\"));
    }

    /**
     * Deletes users after every test just in case any test adds any.
     */
    @After
    public void deleteUsers() throws Exception {
        ClientYamlTestResponse response = getAdminExecutionContext().callApi("xpack.security.get_user", emptyMap(), emptyList(),
                emptyMap());
        @SuppressWarnings("unchecked")
        Map<String, Object> users = (Map<String, Object>) response.getBody();
        for (String user: users.keySet()) {
            Map<?, ?> metaDataMap = (Map<?, ?>) ((Map<?, ?>) users.get(user)).get("metadata");
            Boolean reserved = metaDataMap == null ? null : (Boolean) metaDataMap.get("_reserved");
            if (reserved == null || reserved == false) {
                logger.warn("Deleting leftover user {}", user);
                getAdminExecutionContext().callApi("xpack.security.delete_user", singletonMap("username", user), emptyList(), emptyMap());
            }
        }
    }

    @Override
    protected boolean randomizeContentType() {
        return false;
    }
}
