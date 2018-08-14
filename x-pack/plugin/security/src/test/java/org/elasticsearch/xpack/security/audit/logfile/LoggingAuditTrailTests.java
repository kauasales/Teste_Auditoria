/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.audit.logfile;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.MapBuilder;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.network.NetworkAddress;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.mock.orig.Mockito;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.rest.FakeRestRequest;
import org.elasticsearch.test.rest.FakeRestRequest.Builder;
import org.elasticsearch.transport.TransportMessage;
import org.elasticsearch.xpack.core.security.audit.logfile.CapturingLogger;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.Authentication.RealmRef;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.user.SystemUser;
import org.elasticsearch.protocol.xpack.security.User;
import org.elasticsearch.xpack.security.rest.RemoteHostHeader;
import org.elasticsearch.xpack.security.transport.filter.IPFilter;
import org.elasticsearch.xpack.security.transport.filter.SecurityIpFilterRule;
import org.junit.After;
import org.junit.Before;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LoggingAuditTrailTests extends ESTestCase {

    enum RestContent {
        VALID() {
            @Override
            protected boolean hasContent() {
                return true;
            }

            @Override
            protected BytesReference content() {
                return new BytesArray("{ \"key\": \"value\" }");
            }

            @Override
            protected String expectedMessage() {
                return "{ \"key\": \"value\" }";
            }
        },
        INVALID() {
            @Override
            protected boolean hasContent() {
                return true;
            }

            @Override
            protected BytesReference content() {
                return new BytesArray("{ \"key\": \"value\" ");
            }

            @Override
            protected String expectedMessage() {
                return "{ \"key\": \"value\" ";
            }
        },
        EMPTY() {
            @Override
            protected boolean hasContent() {
                return false;
            }

            @Override
            protected BytesReference content() {
                throw new RuntimeException("should never be called");
            }

            @Override
            protected String expectedMessage() {
                return "";
            }
        };

        protected abstract boolean hasContent();

        protected abstract BytesReference content();

        protected abstract String expectedMessage();
    }

    private Settings settings;
    private DiscoveryNode localNode;
    private ClusterService clusterService;
    private ThreadContext threadContext;
    private boolean includeRequestBody;
    private Map<String, String> commonFields;
    private PatternLayout patternLayout;
    private Logger logger;
    private LoggingAuditTrail auditTrail;

    @Before
    public void init() throws Exception {
        includeRequestBody = randomBoolean();
        settings = Settings.builder()
                .put("xpack.security.audit.logfile.prefix.emit_node_host_address", randomBoolean())
                .put("xpack.security.audit.logfile.prefix.emit_node_host_name", randomBoolean())
                .put("xpack.security.audit.logfile.prefix.emit_node_name", randomBoolean())
                .put("xpack.security.audit.logfile.events.emit_request_body", includeRequestBody)
                .build();
        localNode = mock(DiscoveryNode.class);
        when(localNode.getHostAddress()).thenReturn(buildNewFakeTransportAddress().toString());
        clusterService = mock(ClusterService.class);
        when(clusterService.localNode()).thenReturn(localNode);
        Mockito.doAnswer((Answer) invocation -> {
            final LoggingAuditTrail arg0 = (LoggingAuditTrail) invocation.getArguments()[0];
            arg0.updateLocalNodeInfo(localNode);
            return null;
        }).when(clusterService).addListener(Mockito.isA(LoggingAuditTrail.class));
        final ClusterSettings clusterSettings = mockClusterSettings();
        when(clusterService.getClusterSettings()).thenReturn(clusterSettings);
        commonFields = new LoggingAuditTrail.EntryCommonFields(settings, localNode).commonFields;
        threadContext = new ThreadContext(Settings.EMPTY);
        if (randomBoolean()) {
            threadContext.putHeader(Task.X_OPAQUE_ID, randomAlphaOfLengthBetween(1, 4));
        }
        patternLayout = PatternLayout.newBuilder().withPattern(
                "{" +
                "\"timestamp\":\"%d{ISO8601}\"" +
                "%varsNotEmpty{, \"node.name\":\"%enc{%map{node.name}}{JSON}\"}" +
                "%varsNotEmpty{, \"host.name\":\"%enc{%map{host.name}}{JSON}\"}" +
                "%varsNotEmpty{, \"host.ip\":\"%enc{%map{host.ip}}{JSON}\"}" +
                "%varsNotEmpty{, \"event.type\":\"%enc{%map{event.type}}{JSON}\"}" +
                "%varsNotEmpty{, \"event.action\":\"%enc{%map{event.action}}{JSON}\"}" +
                "%varsNotEmpty{, \"user.name\":\"%enc{%map{user.name}}{JSON}\"}" +
                "%varsNotEmpty{, \"user.run_by.name\":\"%enc{%map{user.run_by.name}}{JSON}\"}" +
                "%varsNotEmpty{, \"user.run_as.name\":\"%enc{%map{user.run_as.name}}{JSON}\"}" +
                "%varsNotEmpty{, \"user.realm\":\"%enc{%map{user.realm}}{JSON}\"}" +
                "%varsNotEmpty{, \"user.run_by.realm\":\"%enc{%map{user.run_by.realm}}{JSON}\"}" +
                "%varsNotEmpty{, \"user.run_as.realm\":\"%enc{%map{user.run_as.realm}}{JSON}\"}" +
                "%varsNotEmpty{, \"user.roles\":\"%enc{%map{user.roles}}{JSON}\"}" +
                "%varsNotEmpty{, \"origin.type\":\"%enc{%map{origin.type}}{JSON}\"}" +
                "%varsNotEmpty{, \"origin.address\":\"%enc{%map{origin.address}}{JSON}\"}" +
                "%varsNotEmpty{, \"realm\":\"%enc{%map{realm}}{JSON}\"}" +
                "%varsNotEmpty{, \"url.path\":\"%enc{%map{url.path}}{JSON}\"}" +
                "%varsNotEmpty{, \"url.query\":\"%enc{%map{url.query}}{JSON}\"}" +
                "%varsNotEmpty{, \"request.body\":\"%enc{%map{request.body}}{JSON}\"}" +
                "%varsNotEmpty{, \"action\":\"%enc{%map{action}}{JSON}\"}" +
                "%varsNotEmpty{, \"request.name\":\"%enc{%map{request.name}}{JSON}\"}" +
                "%varsNotEmpty{, \"indices\":\"%enc{%map{indices}}{JSON}\"}" +
                "%varsNotEmpty{, \"opaque_id\":\"%enc{%map{opaque_id}}{JSON}\"}" +
                "%varsNotEmpty{, \"transport.profile\":\"%enc{%map{transport.profile}}{JSON}\"}" +
                "%varsNotEmpty{, \"rule\":\"%enc{%map{rule}}{JSON}\"}" +
                "%varsNotEmpty{, \"event.category\":\"%enc{%map{event.category}}{JSON}\"}" +
                "}%n")
                .withCharset(StandardCharsets.UTF_8)
                .build();
        logger = CapturingLogger.newCapturingLogger(Level.INFO, patternLayout);
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
    }

    @After
    public void clearLog() throws Exception {
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
    }

    public void testAnonymousAccessDeniedTransport() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);

        auditTrail.anonymousAccessDenied("_action", message);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "anonymous_access_denied")
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action");
        indicesRequest(message, checkedFields);
        restOrTransportOrigin(message, threadContext, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "anonymous_access_denied")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.anonymousAccessDenied("_action", message);
        assertEmptyLog(logger);
    }

    public void testAnonymousAccessDeniedRest() throws Exception {
        final InetAddress address = forge("_hostname", randomBoolean() ? "127.0.0.1" : "::1");
        final Tuple<RestContent, RestRequest> tuple = prepareRestContent("_uri", new InetSocketAddress(address, 9200));
        final String expectedMessage = tuple.v1().expectedMessage();
        final RestRequest request = tuple.v2();

        auditTrail.anonymousAccessDenied(request);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "anonymous_access_denied")
                .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(address))
                .put(LoggingAuditTrail.REQUEST_BODY_FIELD_NAME,
                        includeRequestBody && Strings.hasLength(expectedMessage) ? expectedMessage : null)
                .put(LoggingAuditTrail.URL_PATH_FIELD_NAME, "_uri")
                .put(LoggingAuditTrail.URL_QUERY_FIELD_NAME, null);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "anonymous_access_denied")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.anonymousAccessDenied(request);
        assertEmptyLog(logger);
    }

    public void testAuthenticationFailed() throws Exception {
        final AuthenticationToken mockToken = new MockToken();
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);

        auditTrail.authenticationFailed(mockToken, "_action", message);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "authentication_failed")
                     .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                     .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, mockToken.principal())
                     .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "authentication_failed")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationFailed(new MockToken(), "_action", message);
        assertEmptyLog(logger);
    }

    public void testAuthenticationFailedNoToken() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);

        auditTrail.authenticationFailed("_action", message);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "authentication_failed")
                     .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                     .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, null)
                     .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "authentication_failed")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationFailed("_action", message);
        assertEmptyLog(logger);
    }

    public void testAuthenticationFailedRest() throws Exception {
        final Map<String, String> params = new HashMap<>();
        if (randomBoolean()) {
            params.put("foo", "bar");
        }
        final InetAddress address = forge("_hostname", randomBoolean() ? "127.0.0.1" : "::1");
        final Tuple<RestContent, RestRequest> tuple = prepareRestContent("_uri", new InetSocketAddress(address, 9200), params);
        final String expectedMessage = tuple.v1().expectedMessage();
        final RestRequest request = tuple.v2();
        final AuthenticationToken mockToken = new MockToken();

        auditTrail.authenticationFailed(mockToken, request);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "authentication_failed")
                     .put(LoggingAuditTrail.ACTION_FIELD_NAME, null)
                     .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, mockToken.principal())
                     .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(address))
                     .put(LoggingAuditTrail.REQUEST_BODY_FIELD_NAME,
                             includeRequestBody && Strings.hasLength(expectedMessage) ? expectedMessage : null)
                     .put(LoggingAuditTrail.URL_PATH_FIELD_NAME, "_uri")
                     .put(LoggingAuditTrail.URL_QUERY_FIELD_NAME, params.isEmpty() ? null : "foo=bar");
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "authentication_failed")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationFailed(new MockToken(), request);
        assertEmptyLog(logger);
    }

    public void testAuthenticationFailedRestNoToken() throws Exception {
        final Map<String, String> params = new HashMap<>();
        if (randomBoolean()) {
            params.put("bar", "baz");
        }
        final InetAddress address = forge("_hostname", randomBoolean() ? "127.0.0.1" : "::1");
        final Tuple<RestContent, RestRequest> tuple = prepareRestContent("_uri", new InetSocketAddress(address, 9200), params);
        final String expectedMessage = tuple.v1().expectedMessage();
        final RestRequest request = tuple.v2();

        auditTrail.authenticationFailed(request);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "authentication_failed")
                     .put(LoggingAuditTrail.ACTION_FIELD_NAME, null)
                     .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, null)
                     .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(address))
                     .put(LoggingAuditTrail.REQUEST_BODY_FIELD_NAME,
                             includeRequestBody && Strings.hasLength(expectedMessage) ? expectedMessage : null)
                     .put(LoggingAuditTrail.URL_PATH_FIELD_NAME, "_uri")
                     .put(LoggingAuditTrail.URL_QUERY_FIELD_NAME, params.isEmpty() ? null : "bar=baz");
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "authentication_failed")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationFailed(request);
        assertEmptyLog(logger);
    }

    public void testAuthenticationFailedRealm() throws Exception {
        final AuthenticationToken mockToken = new MockToken();
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final String realm = randomAlphaOfLengthBetween(1, 6);
        auditTrail.authenticationFailed(realm, mockToken, "_action", message);
        assertEmptyLog(logger);

        // test enabled
        settings = Settings.builder()
                       .put(settings)
                       .put("xpack.security.audit.logfile.events.include", "realm_authentication_failed")
                       .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationFailed(realm, mockToken, "_action", message);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "realm_authentication_failed")
                     .put(LoggingAuditTrail.REALM_FIELD_NAME, realm)
                     .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, mockToken.principal())
                     .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                     .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());
    }

    public void testAuthenticationFailedRealmRest() throws Exception {
        final Map<String, String> params = new HashMap<>();
        if (randomBoolean()) {
            params.put("_param", "baz");
        }
        final InetAddress address = forge("_hostname", randomBoolean() ? "127.0.0.1" : "::1");
        final Tuple<RestContent, RestRequest> tuple = prepareRestContent("_uri", new InetSocketAddress(address, 9200), params);
        final String expectedMessage = tuple.v1().expectedMessage();
        final RestRequest request = tuple.v2();
        final AuthenticationToken mockToken = new MockToken();
        final String realm = randomAlphaOfLengthBetween(1, 6);
        auditTrail.authenticationFailed(realm, mockToken, request);
        assertEmptyLog(logger);

        // test enabled
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.include", "realm_authentication_failed")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationFailed(realm, mockToken, request);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "realm_authentication_failed")
                     .put(LoggingAuditTrail.REALM_FIELD_NAME, realm)
                     .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(address))
                     .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, mockToken.principal())
                     .put(LoggingAuditTrail.ACTION_FIELD_NAME, null)
                     .put(LoggingAuditTrail.REQUEST_BODY_FIELD_NAME,
                             includeRequestBody && Strings.hasLength(expectedMessage) ? expectedMessage : null)
                     .put(LoggingAuditTrail.URL_PATH_FIELD_NAME, "_uri")
                     .put(LoggingAuditTrail.URL_QUERY_FIELD_NAME, params.isEmpty() ? null : "_param=baz");
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());
    }

    public void testAccessGranted() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final String role = randomAlphaOfLengthBetween(1, 6);
        final Authentication authentication = createAuthentication();

        auditTrail.accessGranted(authentication, "_action", message, new String[] { role });
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "access_granted")
                .put(LoggingAuditTrail.PRINCIPAL_ROLES_FIELD_NAME, role)
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        subject(authentication, checkedFields);
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "access_granted")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.accessGranted(authentication, "_action", message, new String[] { role });
        assertEmptyLog(logger);
    }

    public void testAccessGrantedInternalSystemAction() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final String role = randomAlphaOfLengthBetween(1, 6);
        final Authentication authentication = new Authentication(SystemUser.INSTANCE, new RealmRef("_reserved", "test", "foo"), null);
        auditTrail.accessGranted(authentication, "internal:_action", message, new String[] { role });
        assertEmptyLog(logger);

        // test enabled
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.include", "system_access_granted")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.accessGranted(authentication, "internal:_action", message, new String[] { role });
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "access_granted")
                .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, SystemUser.INSTANCE.principal())
                .put(LoggingAuditTrail.PRINCIPAL_REALM_FIELD_NAME, "_reserved")
                .put(LoggingAuditTrail.PRINCIPAL_ROLES_FIELD_NAME, role)
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "internal:_action")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());
    }

    public void testAccessGrantedInternalSystemActionNonSystemUser() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final String role = randomAlphaOfLengthBetween(1, 6);
        final Authentication authentication = createAuthentication();

        auditTrail.accessGranted(authentication, "internal:_action", message, new String[] { role });
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "access_granted")
                .put(LoggingAuditTrail.PRINCIPAL_ROLES_FIELD_NAME, role)
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "internal:_action")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        subject(authentication, checkedFields);
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                    .put(settings)
                    .put("xpack.security.audit.logfile.events.exclude", "access_granted")
                    .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.accessGranted(authentication, "internal:_action", message, new String[] { role });
        assertEmptyLog(logger);
    }

    public void testAccessDenied() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final String role = randomAlphaOfLengthBetween(1, 6);
        final Authentication authentication = createAuthentication();

        auditTrail.accessDenied(authentication, "_action/bar", message, new String[] { role });
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "access_denied")
                .put(LoggingAuditTrail.PRINCIPAL_ROLES_FIELD_NAME, role)
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action/bar")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        subject(authentication, checkedFields);
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "access_denied")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.accessDenied(authentication, "_action", message, new String[] { role });
        assertEmptyLog(logger);
    }

    public void testTamperedRequestRest() throws Exception {
        final Map<String, String> params = new HashMap<>();
        if (randomBoolean()) {
            params.put("_param", "baz");
        }
        final InetAddress address = forge("_hostname", randomBoolean() ? "127.0.0.1" : "::1");
        final Tuple<RestContent, RestRequest> tuple = prepareRestContent("_uri", new InetSocketAddress(address, 9200), params);
        final String expectedMessage = tuple.v1().expectedMessage();
        final RestRequest request = tuple.v2();
        auditTrail.tamperedRequest(request);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "tampered_request")
                .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(address))
                .put(LoggingAuditTrail.REQUEST_BODY_FIELD_NAME,
                        includeRequestBody && Strings.hasLength(expectedMessage) ? expectedMessage : null)
                .put(LoggingAuditTrail.URL_PATH_FIELD_NAME, "_uri")
                .put(LoggingAuditTrail.URL_QUERY_FIELD_NAME, params.isEmpty() ? null : "_param=baz");
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "tampered_request")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.tamperedRequest(request);
        assertEmptyLog(logger);
    }

    public void testTamperedRequest() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);

        auditTrail.tamperedRequest("_action", message);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "tampered_request")
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "tampered_request")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.tamperedRequest("_action", message);
        assertEmptyLog(logger);
    }

    public void testTamperedRequestWithUser() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final boolean runAs = randomBoolean();
        final User user;
        if (runAs) {
            user = new User("running_as", new String[] { "r2" }, new User("_username", new String[] { "r1" }));
        } else {
            user = new User("_username", new String[] { "r1" });
        }

        auditTrail.tamperedRequest(user, "_action", message);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "tampered_request")
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        if (runAs) {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "running_as");
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_RUN_BY_FIELD_NAME, "_username");
        } else {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "_username");
        }
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "tampered_request")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.tamperedRequest(user, "_action", message);
        assertEmptyLog(logger);
    }

    public void testConnectionDenied() throws Exception {
        final InetAddress inetAddress = InetAddress.getLoopbackAddress();
        final SecurityIpFilterRule rule = new SecurityIpFilterRule(false, "_all");
        final String profile = randomAlphaOfLengthBetween(1, 6);

        auditTrail.connectionDenied(inetAddress, profile, rule);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.IP_FILTER_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "connection_denied")
                .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.IP_FILTER_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(inetAddress))
                .put(LoggingAuditTrail.TRANSPORT_PROFILE_FIELD_NAME, profile)
                .put(LoggingAuditTrail.RULE_FIELD_NAME, "deny _all");
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "connection_denied")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.connectionDenied(inetAddress, profile, rule);
        assertEmptyLog(logger);
    }

    public void testConnectionGranted() throws Exception {
        final InetAddress inetAddress = InetAddress.getLoopbackAddress();
        final SecurityIpFilterRule rule = IPFilter.DEFAULT_PROFILE_ACCEPT_ALL;
        final String profile = randomAlphaOfLengthBetween(1, 6);

        auditTrail.connectionGranted(inetAddress, profile, rule);
        assertEmptyLog(logger);

        // test enabled
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.include", "connection_granted")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.connectionGranted(inetAddress, profile, rule);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.IP_FILTER_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "connection_granted")
                .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.IP_FILTER_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(inetAddress))
                .put(LoggingAuditTrail.TRANSPORT_PROFILE_FIELD_NAME, profile)
                .put(LoggingAuditTrail.RULE_FIELD_NAME, "allow default:accept_all");
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());
    }

    public void testRunAsGranted() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final String role = randomAlphaOfLengthBetween(1, 6);
        final Authentication authentication = new Authentication(
                new User("running as", new String[] { "r2" }, new User("_username", new String[] { "r1" })),
                new RealmRef("authRealm", "test", "foo"),
                new RealmRef("lookRealm", "up", "by"));

        auditTrail.runAsGranted(authentication, "_action", message, new String[] { role });
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "run_as_granted")
                .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "_username")
                .put(LoggingAuditTrail.PRINCIPAL_REALM_FIELD_NAME, "authRealm")
                .put(LoggingAuditTrail.PRINCIPAL_RUN_AS_FIELD_NAME, "running as")
                .put(LoggingAuditTrail.PRINCIPAL_RUN_AS_REALM_FIELD_NAME, "lookRealm")
                .put(LoggingAuditTrail.PRINCIPAL_ROLES_FIELD_NAME, role)
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "run_as_granted")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.runAsGranted(authentication, "_action", message, new String[] { role });
        assertEmptyLog(logger);
    }

    public void testRunAsDenied() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final String role = randomAlphaOfLengthBetween(1, 6);
        final Authentication authentication = new Authentication(
                new User("running as", new String[] { "r2" }, new User("_username", new String[] { "r1" })),
                new RealmRef("authRealm", "test", "foo"),
                new RealmRef("lookRealm", "up", "by"));

        auditTrail.runAsDenied(authentication, "_action", message, new String[] { role });
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "run_as_denied")
                .put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "_username")
                .put(LoggingAuditTrail.PRINCIPAL_REALM_FIELD_NAME, "authRealm")
                .put(LoggingAuditTrail.PRINCIPAL_RUN_AS_FIELD_NAME, "running as")
                .put(LoggingAuditTrail.PRINCIPAL_RUN_AS_REALM_FIELD_NAME, "lookRealm")
                .put(LoggingAuditTrail.PRINCIPAL_ROLES_FIELD_NAME, role)
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());

        // test disabled
        CapturingLogger.output(logger.getName(), Level.INFO).clear();
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.exclude", "run_as_denied")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.runAsDenied(authentication, "_action", message, new String[] { role });
        assertEmptyLog(logger);
    }

    public void testAuthenticationSuccessRest() throws Exception {
        final Map<String, String> params = new HashMap<>();
        if (randomBoolean()) {
            params.put("foo", "bar");
            params.put("evac", "true");
        }
        final InetAddress address = forge("_hostname", randomBoolean() ? "127.0.0.1" : "::1");
        final Tuple<RestContent, RestRequest> tuple = prepareRestContent("_uri", new InetSocketAddress(address, 9200), params);
        final String expectedMessage = tuple.v1().expectedMessage();
        final RestRequest request = tuple.v2();
        final String realm = randomAlphaOfLengthBetween(1, 6);
        final User user;
        if (randomBoolean()) {
            user = new User("running as", new String[] { "r2" }, new User("_username", new String[] { "r1" }));
        } else {
            user = new User("_username", new String[] { "r1" });
        }

        // event by default disabled
        auditTrail.authenticationSuccess(realm, user, request);
        assertEmptyLog(logger);

        settings = Settings.builder()
                .put(this.settings)
                .put("xpack.security.audit.logfile.events.include", "authentication_success")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationSuccess(realm, user, request);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "authentication_success")
                     .put(LoggingAuditTrail.REALM_FIELD_NAME, realm)
                     .put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                     .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(address))
                     .put(LoggingAuditTrail.REQUEST_BODY_FIELD_NAME,
                             includeRequestBody && Strings.hasLength(expectedMessage) ? expectedMessage : null)
                     .put(LoggingAuditTrail.URL_PATH_FIELD_NAME, "_uri")
                     .put(LoggingAuditTrail.URL_QUERY_FIELD_NAME, params.isEmpty() ? null : "foo=bar&evac=true");
        if (user.isRunAs()) {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "running as");
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_RUN_BY_FIELD_NAME, "_username");
        } else {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "_username");
        }
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());
    }

    public void testAuthenticationSuccessTransport() throws Exception {
        final TransportMessage message = randomBoolean() ? new MockMessage(threadContext) : new MockIndicesRequest(threadContext);
        final User user;
        if (randomBoolean()) {
            user = new User("running as", new String[] { "r2" }, new User("_username", new String[] { "r1" }));
        } else {
            user = new User("_username", new String[] { "r1" });
        }
        final String realm = randomAlphaOfLengthBetween(1, 6);

        // event by default disabled
        auditTrail.authenticationSuccess(realm, user, "_action", message);
        assertEmptyLog(logger);

        settings = Settings.builder()
                .put(this.settings)
                .put("xpack.security.audit.logfile.events.include", "authentication_success")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        auditTrail.authenticationSuccess(realm, user, "_action", message);
        final MapBuilder<String, String> checkedFields = new MapBuilder<>(commonFields);
        checkedFields.put(LoggingAuditTrail.EVENT_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                .put(LoggingAuditTrail.EVENT_ACTION_FIELD_NAME, "authentication_success")
                .put(LoggingAuditTrail.ACTION_FIELD_NAME, "_action")
                .put(LoggingAuditTrail.REALM_FIELD_NAME, realm)
                .put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, message.getClass().getSimpleName());
        if (user.isRunAs()) {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "running as");
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_RUN_BY_FIELD_NAME, "_username");
        } else {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, "_username");
        }
        restOrTransportOrigin(message, threadContext, checkedFields);
        indicesRequest(message, checkedFields);
        opaqueId(threadContext, checkedFields);
        assertMsg(logger, checkedFields.immutableMap());
    }

    public void testRequestsWithoutIndices() throws Exception {
        settings = Settings.builder()
                .put(settings)
                .put("xpack.security.audit.logfile.events.include", "_all")
                .build();
        auditTrail = new LoggingAuditTrail(settings, clusterService, logger, threadContext);
        final User user = new User("_username", new String[] { "r1" });
        final String role = randomAlphaOfLengthBetween(1, 6);
        final String realm = randomAlphaOfLengthBetween(1, 6);
        // transport messages without indices
        final TransportMessage[] messages = new TransportMessage[] { new MockMessage(threadContext),
                new org.elasticsearch.action.MockIndicesRequest(IndicesOptions.strictExpandOpenAndForbidClosed(), new String[0]),
                new org.elasticsearch.action.MockIndicesRequest(IndicesOptions.strictExpandOpenAndForbidClosed(), (String[]) null) };
        final List<String> output = CapturingLogger.output(logger.getName(), Level.INFO);
        int logEntriesCount = 1;
        for (final TransportMessage message : messages) {
            auditTrail.anonymousAccessDenied("_action", message);
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.authenticationFailed(new MockToken(), "_action", message);
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.authenticationFailed("_action", message);
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.authenticationFailed(realm, new MockToken(), "_action", message);
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.accessGranted(createAuthentication(), "_action", message, new String[] { role });
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.accessDenied(createAuthentication(), "_action", message, new String[] { role });
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.tamperedRequest("_action", message);
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.tamperedRequest(user, "_action", message);
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.runAsGranted(createAuthentication(), "_action", message, new String[] { role });
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.runAsDenied(createAuthentication(), "_action", message, new String[] { role });
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
            auditTrail.authenticationSuccess(realm, user, "_action", message);
            assertThat(output.size(), is(logEntriesCount++));
            assertThat(output.get(logEntriesCount - 2), not(containsString("indices=")));
        }
    }

    private void assertMsg(Logger logger, Map<String, String> checkFields) {
        final List<String> output = CapturingLogger.output(logger.getName(), Level.INFO);
        assertThat("Exactly one logEntry expected. Found: " + output.size(), output.size(), is(1));
        if (checkFields == null) {
            // only check msg existence
            return;
        }
        String logLine = output.get(0);
        // check each field
        for (final Map.Entry<String, String> checkField : checkFields.entrySet()) {
            if (null == checkField.getValue()) {
                // null checkField means that the field does not exist
                assertThat("Field: " + checkField.getKey() + " should be missing.", logLine.contains(Pattern.quote(checkField.getKey())),
                        is(false));
            } else {
                final Pattern logEntryFieldPattern = Pattern.compile(
                        Pattern.quote("\"" + checkField.getKey() + "\":\"" + checkField.getValue().replaceAll("\"", "\\\\\"") + "\""));
                assertThat("Field " + checkField.getKey() + " value mismatch. Expected " + checkField.getValue(),
                        logEntryFieldPattern.matcher(logLine).find(), is(true));
                // remove checked field
                logLine = logEntryFieldPattern.matcher(logLine).replaceFirst("");
            }
        }
        logLine = logLine.replaceFirst("\"timestamp\":\"[^\"]*\"", "").replaceAll("[{},]", "");
        // check no extra fields
        assertThat("Log event has extra unexpected content: " + logLine, Strings.hasText(logLine), is(false));
    }

    private void assertEmptyLog(Logger logger) {
        assertThat("Logger is not empty", CapturingLogger.isEmpty(logger.getName()), is(true));
    }

    protected Tuple<RestContent, RestRequest> prepareRestContent(String uri, InetSocketAddress remoteAddress) {
        return prepareRestContent(uri, remoteAddress, Collections.emptyMap());
    }

    private Tuple<RestContent, RestRequest> prepareRestContent(String uri, InetSocketAddress remoteAddress, Map<String, String> params) {
        final RestContent content = randomFrom(RestContent.values());
        final FakeRestRequest.Builder builder = new Builder(NamedXContentRegistry.EMPTY);
        if (content.hasContent()) {
            builder.withContent(content.content(), XContentType.JSON);
        }
        builder.withPath(uri);
        builder.withRemoteAddress(remoteAddress);
        builder.withParams(params);
        return new Tuple<>(content, builder.build());
    }

    /** creates address without any lookups. hostname can be null, for missing */
    protected static InetAddress forge(String hostname, String address) throws IOException {
        final byte bytes[] = InetAddress.getByName(address).getAddress();
        return InetAddress.getByAddress(hostname, bytes);
    }

    private static String indices(TransportMessage message) {
        return Strings.arrayToCommaDelimitedString(((IndicesRequest) message).indices());
    }

    private static Authentication createAuthentication() {
        final RealmRef lookedUpBy;
        final User user;
        if (randomBoolean()) {
            user = new User("running_as", new String[] { "r2" }, new User("_username", new String[] { "r1" }));
            lookedUpBy = new RealmRef("lookRealm", "up", "by");
        } else {
            user = new User("_username", new String[] { "r1" });
            lookedUpBy = null;
        }
        return new Authentication(user, new RealmRef("authRealm", "test", "foo"), lookedUpBy);
    }

    private ClusterSettings mockClusterSettings() {
        final List<Setting<?>> settingsList = new ArrayList<>();
        LoggingAuditTrail.registerSettings(settingsList);
        settingsList.addAll(ClusterSettings.BUILT_IN_CLUSTER_SETTINGS);
        return new ClusterSettings(settings, new HashSet<>(settingsList));
    }

    static class MockMessage extends TransportMessage {

        MockMessage(ThreadContext threadContext) throws IOException {
            if (randomBoolean()) {
                if (randomBoolean()) {
                    remoteAddress(buildNewFakeTransportAddress());
                } else {
                    remoteAddress(new TransportAddress(InetAddress.getLoopbackAddress(), 1234));
                }
            }
            if (randomBoolean()) {
                RemoteHostHeader.putRestRemoteAddress(threadContext, new InetSocketAddress(forge("localhost", "127.0.0.1"), 1234));
            }
        }
    }

    static class MockIndicesRequest extends org.elasticsearch.action.MockIndicesRequest {

        MockIndicesRequest(ThreadContext threadContext) throws IOException {
            super(IndicesOptions.strictExpandOpenAndForbidClosed(), "idx1", "idx2");
            if (randomBoolean()) {
                remoteAddress(buildNewFakeTransportAddress());
            }
            if (randomBoolean()) {
                RemoteHostHeader.putRestRemoteAddress(threadContext, new InetSocketAddress(forge("localhost", "127.0.0.1"), 1234));
            }
        }

        @Override
        public String toString() {
            return "mock-message";
        }
    }

    private static class MockToken implements AuthenticationToken {
        @Override
        public String principal() {
            return "_principal";
        }

        @Override
        public Object credentials() {
            fail("it's not allowed to print the credentials of the auth token");
            return null;
        }

        @Override
        public void clearCredentials() {

        }
    }

    private static void restOrTransportOrigin(TransportMessage message, ThreadContext threadContext,
                                              MapBuilder<String, String> checkedFields) {
        final InetSocketAddress restAddress = RemoteHostHeader.restRemoteAddress(threadContext);
        if (restAddress != null) {
            checkedFields.put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.REST_ORIGIN_FIELD_VALUE)
                    .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(restAddress.getAddress()));
        } else {
            final TransportAddress address = message.remoteAddress();
            if (address != null) {
                checkedFields.put(LoggingAuditTrail.ORIGIN_TYPE_FIELD_NAME, LoggingAuditTrail.TRANSPORT_ORIGIN_FIELD_VALUE)
                        .put(LoggingAuditTrail.ORIGIN_ADDRESS_FIELD_NAME, NetworkAddress.format(address.address().getAddress()));
            }
        }
    }

    private static void subject(Authentication authentication, MapBuilder<String, String> checkedFields) {
        checkedFields.put(LoggingAuditTrail.PRINCIPAL_FIELD_NAME, authentication.getUser().principal());
        if (authentication.getUser().isRunAs()) {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_REALM_FIELD_NAME, authentication.getLookedUpBy().getName())
                         .put(LoggingAuditTrail.PRINCIPAL_RUN_BY_FIELD_NAME, authentication.getUser().authenticatedUser().principal())
                         .put(LoggingAuditTrail.PRINCIPAL_RUN_BY_REALM_FIELD_NAME, authentication.getAuthenticatedBy().getName());
        } else {
            checkedFields.put(LoggingAuditTrail.PRINCIPAL_REALM_FIELD_NAME, authentication.getAuthenticatedBy().getName());
        }
    }

    private static void opaqueId(ThreadContext threadContext, MapBuilder<String, String> checkedFields) {
        final String opaqueId = threadContext.getHeader(Task.X_OPAQUE_ID);
        if (opaqueId != null) {
            checkedFields.put(LoggingAuditTrail.OPAQUE_ID_FIELD_NAME, opaqueId);
        } else {
            checkedFields.put(LoggingAuditTrail.OPAQUE_ID_FIELD_NAME, null);
        }
    }

    private static void indicesRequest(TransportMessage message, MapBuilder<String, String> checkedFields) {
        if (message instanceof IndicesRequest) {
            checkedFields.put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, MockIndicesRequest.class.getSimpleName());
            checkedFields.put(LoggingAuditTrail.INDICES_FIELD_NAME, indices(message));
        } else {
            checkedFields.put(LoggingAuditTrail.REQUEST_NAME_FIELD_NAME, MockMessage.class.getSimpleName());
            checkedFields.put(LoggingAuditTrail.INDICES_FIELD_NAME, null);
        }
    }

}
