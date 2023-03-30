/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.application.analytics;

import org.elasticsearch.ResourceNotFoundException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.application.analytics.action.PostAnalyticsEventAction;
import org.elasticsearch.xpack.application.analytics.event.AnalyticsEvent;
import org.elasticsearch.xpack.application.analytics.event.AnalyticsEventFactory;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AnalyticsEventEmitterServiceTests extends ESTestCase {
    public void testEmitEventWhenCollectionExists() throws IOException {
        // Preparing a randomRequest.
        PostAnalyticsEventAction.Request request = randomRequest();

        // Stubbing emitted event.
        AnalyticsEvent emittedEvent = mock(AnalyticsEvent.class);
        when(emittedEvent.eventCollectionName()).thenReturn(request.eventCollectionName());
        when(emittedEvent.eventType()).thenReturn(request.eventType());
        when(emittedEvent.eventTime()).thenReturn(request.eventTime());

        // Stubbing parsing to emit mock events.
        AnalyticsEventFactory analyticsEventFactoryMock = mock(AnalyticsEventFactory.class);
        when(analyticsEventFactoryMock.fromRequest(request)).thenReturn(emittedEvent);

        // Mocking event logger.
        AnalyticsEventLogger eventLogger = mock(AnalyticsEventLogger.class);

        // Create the event emitter
        AnalyticsEventEmitterService eventEmitter = new AnalyticsEventEmitterService(
            analyticsEventFactoryMock,
            mock(AnalyticsCollectionResolver.class),
            mock(ClusterService.class),
            eventLogger
        );

        @SuppressWarnings("unchecked")
        ActionListener<PostAnalyticsEventAction.Response> listener = mock(ActionListener.class);

        // Send the event.
        eventEmitter.emitEvent(request, listener);

        // Check no exception has been raised and the accepted response is sent.
        verify(listener, never()).onFailure(any());
        verify(listener).onResponse(argThat((PostAnalyticsEventAction.Response response) -> {
            assertTrue(response.isAccepted());
            assertEquals(response.isDebug(), request.isDebug());
            if (response.isDebug()) {
                assertEquals(((PostAnalyticsEventAction.DebugResponse) response).analyticsEvent(), emittedEvent);
            }

            return response.isAccepted();
        }));

        // Check event have been passed to the logger.
        verify(eventLogger).logEvent(emittedEvent);
    }

    public void testEmitEventWhenCollectionDoesNotExists() throws IOException {
        // Preparing a randomRequest
        PostAnalyticsEventAction.Request request = randomRequest();

        // Mocking event logger.
        AnalyticsEventLogger eventLogger = mock(AnalyticsEventLogger.class);

        // Create the event emitter
        AnalyticsCollectionResolver analyticsCollectionResolver = mock(AnalyticsCollectionResolver.class);
        when(analyticsCollectionResolver.collection(any(), eq(request.eventCollectionName()))).thenThrow(ResourceNotFoundException.class);
        AnalyticsEventEmitterService eventEmitter = new AnalyticsEventEmitterService(
            mock(AnalyticsEventFactory.class),
            analyticsCollectionResolver,
            mock(ClusterService.class),
            eventLogger
        );

        @SuppressWarnings("unchecked")
        ActionListener<PostAnalyticsEventAction.Response> listener = mock(ActionListener.class);

        // Emit the event
        eventEmitter.emitEvent(request, listener);

        // Verify responding through onFailure
        verify(listener, never()).onResponse(any());
        verify(listener).onFailure(any(ResourceNotFoundException.class));

        // Verify no event is logged
        verify(eventLogger, never()).logEvent(any());
    }

    public void testEmitEventWhenParsingError() throws IOException {
        // Preparing a randomRequest
        PostAnalyticsEventAction.Request request = randomRequest();

        // Mocking event logger.
        AnalyticsEventLogger eventLogger = mock(AnalyticsEventLogger.class);

        // Create the event emitter
        AnalyticsEventFactory analyticsEventFactory = mock(AnalyticsEventFactory.class);
        when(analyticsEventFactory.fromRequest(request)).thenThrow(IOException.class);
        AnalyticsEventEmitterService eventEmitter = new AnalyticsEventEmitterService(
            analyticsEventFactory,
            mock(AnalyticsCollectionResolver.class),
            mock(ClusterService.class),
            eventLogger
        );

        @SuppressWarnings("unchecked")
        ActionListener<PostAnalyticsEventAction.Response> listener = mock(ActionListener.class);

        // Emit the event
        eventEmitter.emitEvent(request, listener);

        // Verify responding through onFailure
        verify(listener, never()).onResponse(any());
        verify(listener).onFailure(any(IOException.class));

        // Verify no event is logged
        verify(eventLogger, never()).logEvent(any());
    }

    private PostAnalyticsEventAction.Request randomRequest() {
        String eventType = randomFrom(AnalyticsEvent.Type.values()).toString();
        return new PostAnalyticsEventAction.Request(
            randomIdentifier(),
            eventType,
            randomBoolean(),
            XContentType.JSON,
            new BytesArray(randomIdentifier())
        );
    }
}
