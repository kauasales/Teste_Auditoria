/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.transport.netty4;

import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.DefaultLastHttpContent;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.ssl.SslHandler;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.MockSecureSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.ssl.SslClientAuthenticationMode;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.TestEnvironment;
import org.elasticsearch.http.AbstractHttpServerTransportTestCase;
import org.elasticsearch.http.NullDispatcher;
import org.elasticsearch.http.netty4.HttpHeadersUtils;
import org.elasticsearch.http.netty4.Netty4HttpResponse;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.threadpool.TestThreadPool;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.tracing.Tracer;
import org.elasticsearch.transport.netty4.SharedGroupFactory;
import org.elasticsearch.transport.netty4.TLSConfig;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.ssl.SSLService;
import org.elasticsearch.xpack.security.Security;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.net.ssl.SSLEngine;

import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;
import static org.elasticsearch.transport.Transports.TEST_MOCK_TRANSPORT_THREAD_PREFIX;
import static org.elasticsearch.xpack.security.transport.netty4.SimpleSecurityNetty4ServerTransportTests.randomCapitalization;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.mock;

public class SecurityNetty4HttpServerTransportTests extends AbstractHttpServerTransportTestCase {

    private SSLService sslService;
    private Environment env;
    private Path testnodeCert;
    private Path testnodeKey;

    @Before
    public void createSSLService() {
        testnodeCert = getDataPath("/org/elasticsearch/xpack/security/transport/ssl/certs/simple/testnode.crt");
        testnodeKey = getDataPath("/org/elasticsearch/xpack/security/transport/ssl/certs/simple/testnode.pem");

        MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString("xpack.security.http.ssl.secure_key_passphrase", "testnode");
        Settings settings = Settings.builder()
            .put("xpack.security.http.ssl.enabled", true)
            .put("xpack.security.http.ssl.key", testnodeKey)
            .put("xpack.security.http.ssl.certificate", testnodeCert)
            .put("path.home", createTempDir())
            .setSecureSettings(secureSettings)
            .build();
        env = TestEnvironment.newEnvironment(settings);
        sslService = new SSLService(env);
    }

    public void testDefaultClientAuth() throws Exception {
        Settings settings = Settings.builder().put(env.settings()).put(XPackSettings.HTTP_SSL_ENABLED.getKey(), true).build();
        sslService = new SSLService(TestEnvironment.newEnvironment(settings));
        Netty4HttpServerTransport transport = new Netty4HttpServerTransport(
            settings,
            new NetworkService(Collections.emptyList()),
            mock(ThreadPool.class),
            xContentRegistry(),
            new NullDispatcher(),
            randomClusterSettings(),
            new SharedGroupFactory(settings),
            Tracer.NOOP,
            new TLSConfig(sslService.getHttpTransportSSLConfiguration(), sslService::createSSLEngine),
            null,
            randomFrom(VALIDATE_EVERYTHING_VALIDATOR, null)
        );
        ChannelHandler handler = transport.configureServerChannelHandler();
        final EmbeddedChannel ch = new EmbeddedChannel(handler);
        assertThat(ch.pipeline().get(SslHandler.class).engine().getNeedClientAuth(), is(false));
        assertThat(ch.pipeline().get(SslHandler.class).engine().getWantClientAuth(), is(false));
    }

    public void testOptionalClientAuth() throws Exception {
        String value = randomCapitalization(SslClientAuthenticationMode.OPTIONAL);
        Settings settings = Settings.builder()
            .put(env.settings())
            .put(XPackSettings.HTTP_SSL_ENABLED.getKey(), true)
            .put("xpack.security.http.ssl.client_authentication", value)
            .build();
        sslService = new SSLService(TestEnvironment.newEnvironment(settings));
        Netty4HttpServerTransport transport = new Netty4HttpServerTransport(
            settings,
            new NetworkService(Collections.emptyList()),
            mock(ThreadPool.class),
            xContentRegistry(),
            new NullDispatcher(),
            randomClusterSettings(),
            new SharedGroupFactory(settings),
            Tracer.NOOP,
            new TLSConfig(sslService.getHttpTransportSSLConfiguration(), sslService::createSSLEngine),
            null,
            randomFrom(VALIDATE_EVERYTHING_VALIDATOR, null)
        );
        ChannelHandler handler = transport.configureServerChannelHandler();
        final EmbeddedChannel ch = new EmbeddedChannel(handler);
        assertThat(ch.pipeline().get(SslHandler.class).engine().getNeedClientAuth(), is(false));
        assertThat(ch.pipeline().get(SslHandler.class).engine().getWantClientAuth(), is(true));
    }

    public void testRequiredClientAuth() throws Exception {
        String value = randomCapitalization(SslClientAuthenticationMode.REQUIRED);
        Settings settings = Settings.builder()
            .put(env.settings())
            .put(XPackSettings.HTTP_SSL_ENABLED.getKey(), true)
            .put("xpack.security.http.ssl.client_authentication", value)
            .build();
        sslService = new SSLService(TestEnvironment.newEnvironment(settings));
        Netty4HttpServerTransport transport = new Netty4HttpServerTransport(
            settings,
            new NetworkService(Collections.emptyList()),
            mock(ThreadPool.class),
            xContentRegistry(),
            new NullDispatcher(),
            randomClusterSettings(),
            new SharedGroupFactory(settings),
            Tracer.NOOP,
            new TLSConfig(sslService.getHttpTransportSSLConfiguration(), sslService::createSSLEngine),
            null,
            randomFrom(VALIDATE_EVERYTHING_VALIDATOR, null)
        );
        ChannelHandler handler = transport.configureServerChannelHandler();
        final EmbeddedChannel ch = new EmbeddedChannel(handler);
        assertThat(ch.pipeline().get(SslHandler.class).engine().getNeedClientAuth(), is(true));
        assertThat(ch.pipeline().get(SslHandler.class).engine().getWantClientAuth(), is(false));
    }

    public void testNoClientAuth() throws Exception {
        String value = randomCapitalization(SslClientAuthenticationMode.NONE);
        Settings settings = Settings.builder()
            .put(env.settings())
            .put(XPackSettings.HTTP_SSL_ENABLED.getKey(), true)
            .put("xpack.security.http.ssl.client_authentication", value)
            .build();
        sslService = new SSLService(TestEnvironment.newEnvironment(settings));
        Netty4HttpServerTransport transport = new Netty4HttpServerTransport(
            settings,
            new NetworkService(Collections.emptyList()),
            mock(ThreadPool.class),
            xContentRegistry(),
            new NullDispatcher(),
            randomClusterSettings(),
            new SharedGroupFactory(settings),
            Tracer.NOOP,
            new TLSConfig(sslService.getHttpTransportSSLConfiguration(), sslService::createSSLEngine),
            null,
            randomFrom(VALIDATE_EVERYTHING_VALIDATOR, null)
        );
        ChannelHandler handler = transport.configureServerChannelHandler();
        final EmbeddedChannel ch = new EmbeddedChannel(handler);
        assertThat(ch.pipeline().get(SslHandler.class).engine().getNeedClientAuth(), is(false));
        assertThat(ch.pipeline().get(SslHandler.class).engine().getWantClientAuth(), is(false));
    }

    public void testCustomSSLConfiguration() throws Exception {
        Settings settings = Settings.builder().put(env.settings()).put(XPackSettings.HTTP_SSL_ENABLED.getKey(), true).build();
        sslService = new SSLService(TestEnvironment.newEnvironment(settings));
        Netty4HttpServerTransport transport = new Netty4HttpServerTransport(
            settings,
            new NetworkService(Collections.emptyList()),
            mock(ThreadPool.class),
            xContentRegistry(),
            new NullDispatcher(),
            randomClusterSettings(),
            new SharedGroupFactory(settings),
            Tracer.NOOP,
            new TLSConfig(sslService.getHttpTransportSSLConfiguration(), sslService::createSSLEngine),
            null,
            randomFrom(VALIDATE_EVERYTHING_VALIDATOR, null)
        );
        ChannelHandler handler = transport.configureServerChannelHandler();
        EmbeddedChannel ch = new EmbeddedChannel(handler);
        SSLEngine defaultEngine = ch.pipeline().get(SslHandler.class).engine();

        settings = Settings.builder()
            .put(env.settings())
            .put(XPackSettings.HTTP_SSL_ENABLED.getKey(), true)
            .put("xpack.security.http.ssl.supported_protocols", "TLSv1.2")
            .build();
        sslService = new SSLService(TestEnvironment.newEnvironment(settings));
        transport = new Netty4HttpServerTransport(
            settings,
            new NetworkService(Collections.emptyList()),
            mock(ThreadPool.class),
            xContentRegistry(),
            new NullDispatcher(),
            randomClusterSettings(),
            new SharedGroupFactory(settings),
            Tracer.NOOP,
            new TLSConfig(sslService.getHttpTransportSSLConfiguration(), sslService::createSSLEngine),
            null,
            randomFrom(VALIDATE_EVERYTHING_VALIDATOR, null)
        );
        handler = transport.configureServerChannelHandler();
        ch = new EmbeddedChannel(handler);
        SSLEngine customEngine = ch.pipeline().get(SslHandler.class).engine();
        assertThat(customEngine.getEnabledProtocols(), arrayContaining("TLSv1.2"));
        assertThat(customEngine.getEnabledProtocols(), not(equalTo(defaultEngine.getEnabledProtocols())));
    }

    public void testNoExceptionWhenConfiguredWithoutSslKeySSLDisabled() throws Exception {
        MockSecureSettings secureSettings = new MockSecureSettings();
        secureSettings.setString("xpack.security.http.ssl.secure_key_passphrase", "testnode");
        Settings settings = Settings.builder()
            .put("xpack.security.http.ssl.enabled", false)
            .put("xpack.security.http.ssl.key", testnodeKey)
            .put("xpack.security.http.ssl.certificate", testnodeCert)
            .setSecureSettings(secureSettings)
            .put("path.home", createTempDir())
            .build();
        env = TestEnvironment.newEnvironment(settings);
        sslService = new SSLService(env);
        Netty4HttpServerTransport transport = new Netty4HttpServerTransport(
            settings,
            new NetworkService(Collections.emptyList()),
            mock(ThreadPool.class),
            xContentRegistry(),
            new NullDispatcher(),
            randomClusterSettings(),
            new SharedGroupFactory(settings),
            Tracer.NOOP,
            new TLSConfig(sslService.getHttpTransportSSLConfiguration(), sslService::createSSLEngine),
            null,
            randomFrom(VALIDATE_EVERYTHING_VALIDATOR, null)
        );
        assertNotNull(transport.configureServerChannelHandler());
    }

    public void testValidationErrors() throws ExecutionException, InterruptedException {
        final Settings settings = Settings.builder().put(env.settings()).build();
        final ThreadPool testThreadPool = new TestThreadPool(TEST_MOCK_TRANSPORT_THREAD_PREFIX);
        try (
            Netty4HttpServerTransport transport = Security.getHttpServerTransportWithHeadersValidator(
                settings,
                new NetworkService(List.of()),
                testThreadPool,
                xContentRegistry(),
                new NullDispatcher(),
                randomClusterSettings(),
                new SharedGroupFactory(settings),
                Tracer.NOOP,
                TLSConfig.noTLS(),
                null,
                VALIDATE_EVERYTHING_VALIDATOR
            )
        ) {
            final ChannelHandler handler = transport.configureServerChannelHandler();
            final EmbeddedChannel ch = new EmbeddedChannel(handler);
            // remove these pipeline handlers as they interfere in the test scenario
            for (String pipelineHandlerName : ch.pipeline().names()) {
                if (pipelineHandlerName.equals("decoder")
                    || pipelineHandlerName.equals("header_validator")
                    || pipelineHandlerName.equals("encoder")
                    || pipelineHandlerName.equals("encoder_compress")
                    || pipelineHandlerName.equals("chunked_writer")) {
                    ch.pipeline().remove(pipelineHandlerName);
                }
            }
            // this tests a request that cannot be validated, but somehow passed authentication
            // this is the case of an erroneous internal state
            var writeFuture = testThreadPool.generic().submit(() -> {
                ch.writeInbound(new DefaultFullHttpRequest(HTTP_1_1, HttpMethod.GET, "/unvalidatable_request"));
                ch.flushInbound();
            });
            writeFuture.get();
            ch.flushOutbound();
            Netty4HttpResponse response = ch.readOutbound();
            assertThat(response.status(), is(HttpResponseStatus.INTERNAL_SERVER_ERROR));
            String responseContentString = new String(ByteBufUtil.getBytes(response.content()), StandardCharsets.UTF_8);
            assertThat(responseContentString, containsString("\"type\":\"security_exception\",\"reason\":\"Request is not validated\""));
            // this tests a request that CAN be validated, but that, somehow, has not been
            writeFuture = testThreadPool.generic().submit(() -> {
                ch.writeInbound(
                    HttpHeadersUtils.wrapAsValidatableMessage(new DefaultHttpRequest(HTTP_1_1, HttpMethod.GET, "/unvalidated_request"))
                );
                ch.writeInbound(new DefaultLastHttpContent());
                ch.flushInbound();
            });
            writeFuture.get();
            ch.flushOutbound();
            response = ch.readOutbound();
            assertThat(response.status(), is(HttpResponseStatus.INTERNAL_SERVER_ERROR));
            responseContentString = new String(ByteBufUtil.getBytes(response.content()), StandardCharsets.UTF_8);
            assertThat(responseContentString, containsString("\"type\":\"security_exception\",\"reason\":\"Request is not validated\""));
            // this tests the case where validation passed and the request is to be dispatched, BUT that the validation context
            // cannot be instated before dispatching the request
            writeFuture = testThreadPool.generic().submit(() -> {
                HttpMessage validatableHttpRequest = HttpHeadersUtils.wrapAsValidatableMessage(
                    new DefaultHttpRequest(HTTP_1_1, HttpMethod.GET, "/unvalidated_request")
                );
                ((HttpHeadersUtils.HttpHeadersWithValidationContext) validatableHttpRequest.headers()).markAsSuccessfullyValidated(() -> {
                    throw new ElasticsearchException("Boom");
                });
                ch.writeInbound(validatableHttpRequest);
                ch.writeInbound(new DefaultLastHttpContent());
                ch.flushInbound();
            });
            writeFuture.get();
            ch.flushOutbound();
            response = ch.readOutbound();
            assertThat(response.status(), is(HttpResponseStatus.INTERNAL_SERVER_ERROR));
            responseContentString = new String(ByteBufUtil.getBytes(response.content()), StandardCharsets.UTF_8);
            assertThat(responseContentString, containsString("\"type\":\"exception\",\"reason\":\"Boom\""));
        } finally {
            testThreadPool.shutdownNow();
        }
    }
}
