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
package org.elasticsearch.test.disruption;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.cluster.ClusterModule;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.test.transport.MockTransport;
import org.elasticsearch.transport.ConnectTransportException;
import org.elasticsearch.transport.RequestHandlerRegistry;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseOptions;

import java.io.IOException;
import java.util.Optional;

import static org.elasticsearch.test.ESTestCase.copyWriteable;
import static org.elasticsearch.transport.TransportService.HANDSHAKE_ACTION_NAME;

public abstract class DisruptableMockTransport extends MockTransport {
    private final Logger logger;

    public DisruptableMockTransport(Logger logger) {
        this.logger = logger;
    }

    protected abstract DiscoveryNode getLocalNode();

    protected abstract ConnectionStatus getConnectionStatus(DiscoveryNode sender, DiscoveryNode destination);

    protected abstract Optional<DisruptableMockTransport> getDisruptedCapturingTransport(DiscoveryNode node, String action);

    protected abstract void handle(DiscoveryNode sender, DiscoveryNode destination, String action, Runnable doDelivery);

    private void sendFromTo(DiscoveryNode sender, DiscoveryNode destination, String action, Runnable doDelivery) {
        handle(sender, destination, action, new Runnable() {
            @Override
            public void run() {
                if (getDisruptedCapturingTransport(destination, action).isPresent()) {
                    doDelivery.run();
                } else {
                    logger.trace("unknown destination in {}", this);
                }
            }

            @Override
            public String toString() {
                return doDelivery.toString();
            }
        });
    }

    @Override
    protected void onSendRequest(long requestId, String action, TransportRequest request, DiscoveryNode destination) {

        assert destination.equals(getLocalNode()) == false : "non-local message from " + getLocalNode() + " to itself";

        final String requestDescription = new ParameterizedMessage("[{}][{}] from {} to {}",
            action, requestId, getLocalNode(), destination).getFormattedMessage();

        final Runnable returnConnectException = new Runnable() {
            @Override
            public void run() {
                handleError(requestId, new ConnectTransportException(destination, "disconnected"));
            }

            @Override
            public String toString() {
                return "disconnection response to " + requestDescription;
            }
        };

        sendFromTo(getLocalNode(), destination, action, new Runnable() {
            @Override
            public void run() {
                switch (getConnectionStatus(getLocalNode(), destination)) {
                    case BLACK_HOLE:
                        if (action.equals(HANDSHAKE_ACTION_NAME)) {
                            // handshakes always have a timeout, and are sent in a blocking fashion, so we must respond with an exception.
                            sendFromTo(destination, getLocalNode(), action, returnConnectException);
                        } else {
                            logger.trace("dropping {}", requestDescription);
                        }
                        break;

                    case DISCONNECTED:
                        sendFromTo(destination, getLocalNode(), action, returnConnectException);
                        break;

                    case CONNECTED:
                        Optional<DisruptableMockTransport> destinationTransport = getDisruptedCapturingTransport(destination, action);
                        assert destinationTransport.isPresent();

                        final RequestHandlerRegistry<TransportRequest> requestHandler =
                            destinationTransport.get().getRequestHandler(action);

                        final TransportChannel transportChannel = new TransportChannel() {
                            @Override
                            public String getProfileName() {
                                return "default";
                            }

                            @Override
                            public String getChannelType() {
                                return "disruptable-mock-transport-channel";
                            }

                            @Override
                            public void sendResponse(final TransportResponse response) {
                                sendFromTo(destination, getLocalNode(), action, new Runnable() {
                                    @Override
                                    public void run() {
                                        if (getConnectionStatus(destination, getLocalNode()) != ConnectionStatus.CONNECTED) {
                                            logger.trace("dropping response to {}: channel is not CONNECTED",
                                                requestDescription);
                                        } else {
                                            handleResponse(requestId, response);
                                        }
                                    }

                                    @Override
                                    public String toString() {
                                        return "response to " + requestDescription;
                                    }
                                });
                            }

                            @Override
                            public void sendResponse(TransportResponse response,
                                                     TransportResponseOptions options) {
                                sendResponse(response);
                            }

                            @Override
                            public void sendResponse(Exception exception) {
                                sendFromTo(destination, getLocalNode(), action, new Runnable() {
                                    @Override
                                    public void run() {
                                        if (getConnectionStatus(destination, getLocalNode()) != ConnectionStatus.CONNECTED) {
                                            logger.trace("dropping response to {}: channel is not CONNECTED",
                                                requestDescription);
                                        } else {
                                            handleRemoteError(requestId, exception);
                                        }
                                    }

                                    @Override
                                    public String toString() {
                                        return "error response to " + requestDescription;
                                    }
                                });
                            }
                        };

                        final TransportRequest copiedRequest;
                        try {
                            copiedRequest = copyWriteable(request, writeableRegistry(), requestHandler::newRequest);
                        } catch (IOException e) {
                            throw new AssertionError("exception de/serializing request", e);
                        }

                        try {
                            requestHandler.processMessageReceived(copiedRequest, transportChannel);
                        } catch (Exception e) {
                            try {
                                transportChannel.sendResponse(e);
                            } catch (Exception ee) {
                                logger.warn("failed to send failure", e);
                            }
                        }
                }
            }

            @Override
            public String toString() {
                return requestDescription;
            }
        });
    }

    private NamedWriteableRegistry writeableRegistry() {
        return new NamedWriteableRegistry(ClusterModule.getNamedWriteables());
    }

    public enum ConnectionStatus {
        CONNECTED,
        DISCONNECTED, // network requests to or from this node throw a ConnectTransportException
        BLACK_HOLE // network traffic to or from the corresponding node is silently discarded
    }
}
