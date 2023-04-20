/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.http.netty4;

import io.netty.channel.Channel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpRequest;

import org.apache.lucene.util.SetOnce;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.TriConsumer;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.HttpHeadersValidationException;
import org.elasticsearch.http.HttpPreRequest;
import org.elasticsearch.rest.RestRequest;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.elasticsearch.http.netty4.Netty4HttpRequest.getHttpHeadersAsMap;
import static org.elasticsearch.http.netty4.Netty4HttpRequest.translateRequestMethod;

/**
 * Provides utilities used to hook into the netty pipeline and run a validation check on each HTTP request's headers.
 * See also {@link Netty4HttpHeaderValidator}.
 */
public final class HttpHeadersUtils {

    /**
     * An async HTTP headers validator function that receives as arguments part of the incoming HTTP request
     * (except the body contents, see {@link HttpPreRequest}), as well as the netty channel that the request is
     * being received over, and must then call the {@code ActionListener#onResponse} method on the listener parameter
     * in case the validation is to be considered successful, or otherwise call {@code ActionListener#onFailure}.
     */
    @FunctionalInterface
    public interface Validator extends TriConsumer<HttpPreRequest, Channel, ActionListener<ThreadContext.StoredContext>> {}

    // utility class
    private HttpHeadersUtils() {}

    /**
     * Supplies a netty {@code ChannelInboundHandler} that runs the provided {@param validator} on the HTTP request headers.
     * The HTTP headers of the to-be-validated {@link HttpRequest} must be wrapped by the special {@link HttpHeadersWithValidationContext},
     * see {@link #wrapAsValidatableMessage(HttpMessage)}.
     */
    public static Netty4HttpHeaderValidator getValidatorInboundHandler(Validator validator) {
        return new Netty4HttpHeaderValidator((httpRequest, channel, listener) -> {
            if (httpRequest.headers() instanceof HttpHeadersWithValidationContext httpHeadersWithValidationContext) {
                // make sure validation only runs on properly wrapped "validatable" headers implementation
                validator.apply(asHttpPreRequest(httpRequest), channel, ActionListener.wrap(validationResult -> {
                    httpHeadersWithValidationContext.markAsSuccessfullyValidated(validationResult);
                    // a successful validation needs to signal to the {@link Netty4HttpHeaderValidator} to resume
                    // forwarding the request beyond the headers part
                    listener.onResponse(null);
                }, e -> listener.onFailure(new HttpHeadersValidationException(e))));
            } else {
                listener.onFailure(new IllegalStateException("Expected a validatable request for validation"));
            }
        });
    }

    /**
     * Given a {@link DefaultHttpRequest} argument, this returns a new {@link DefaultHttpRequest} instance that's identical to the
     * passed-in one, but the headers of the latter are "validatable", in the sense that the channel handlers returned by
     * {@link #getValidatorInboundHandler(Validator)} can use to convey the validation result.
     */
    public static HttpMessage wrapAsValidatableMessage(HttpMessage newlyDecodedMessage) {
        assert newlyDecodedMessage instanceof HttpRequest;
        DefaultHttpRequest httpRequest = (DefaultHttpRequest) newlyDecodedMessage;
        HttpHeadersWithValidationContext httpHeadersWithValidationContext = new HttpHeadersWithValidationContext(
            newlyDecodedMessage.headers()
        );
        return new DefaultHttpRequest(
            httpRequest.protocolVersion(),
            httpRequest.method(),
            httpRequest.uri(),
            httpHeadersWithValidationContext
        );
    }

    public static ThreadContext.StoredContext extractValidationContext(org.elasticsearch.http.HttpRequest request) {
        HttpHeadersWithValidationContext authenticatedHeaders = unwrapValidatableHeaders(request);
        return authenticatedHeaders != null ? authenticatedHeaders.validationResultContextSetOnce.get() : null;
    }

    private static HttpHeadersWithValidationContext unwrapValidatableHeaders(org.elasticsearch.http.HttpRequest request) {
        if (request instanceof Netty4HttpRequest == false) {
            return null;
        }
        if (((Netty4HttpRequest) request).getNettyRequest().headers() instanceof HttpHeadersWithValidationContext == false) {
            return null;
        }
        return (HttpHeadersWithValidationContext) (((Netty4HttpRequest) request).getNettyRequest().headers());
    }

    /**
     * {@link HttpHeaders} implementation that carries along the {@link ThreadContext.StoredContext} iff
     * the HTTP headers have been validated successfully.
     */
    public static final class HttpHeadersWithValidationContext extends DefaultHttpHeaders {

        public final SetOnce<ThreadContext.StoredContext> validationResultContextSetOnce;

        public HttpHeadersWithValidationContext(HttpHeaders httpHeaders) {
            this(httpHeaders, new SetOnce<>());
        }

        private HttpHeadersWithValidationContext(
            HttpHeaders httpHeaders,
            SetOnce<ThreadContext.StoredContext> validationResultContextSetOnce
        ) {
            // the constructor implements the same logic as HttpHeaders#copy
            super();
            set(httpHeaders);
            this.validationResultContextSetOnce = validationResultContextSetOnce;
        }

        private HttpHeadersWithValidationContext(HttpHeaders httpHeaders, ThreadContext.StoredContext validationResult) {
            this(httpHeaders);
            if (validationResult != null) {
                markAsSuccessfullyValidated(validationResult);
            }
        }

        /**
         * Must be called at most once in order to mark the http headers as successfully validated.
         * The intent of the {@link ThreadContext.StoredContext} parameter is to associate the resulting
         * thread context post validation, that can be later restored when dispatching the request.
         */
        public void markAsSuccessfullyValidated(ThreadContext.StoredContext validationResult) {
            this.validationResultContextSetOnce.set(Objects.requireNonNull(validationResult));
        }

        @Override
        public HttpHeaders copy() {
            // copy the headers but also STILL CARRY the same validation result
            return new HttpHeadersWithValidationContext(super.copy(), validationResultContextSetOnce.get());
        }
    }

    /**
     * Translates the netty request internal type to a {@link HttpPreRequest} instance that code outside the network plugin has access to.
     */
    private static HttpPreRequest asHttpPreRequest(HttpRequest request) {
        return new HttpPreRequest() {

            @Override
            public RestRequest.Method method() {
                return translateRequestMethod(request.method());
            }

            @Override
            public String uri() {
                return request.uri();
            }

            @Override
            public Map<String, List<String>> getHeaders() {
                return getHttpHeadersAsMap(request.headers());
            }
        };
    }
}
