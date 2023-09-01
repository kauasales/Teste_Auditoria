/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.transport;

import org.elasticsearch.ElasticsearchWrapperException;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.transport.TransportAddress;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * A remote exception for an action. A wrapper exception around the actual remote cause and does not fill the
 * stack trace.
 */
public class RemoteTransportException extends ActionTransportException implements ElasticsearchWrapperException {

    private String clusterAlias;
    private boolean fatalForCCS;  /// MP TODO: DOCUMENT ME

    public RemoteTransportException(String msg, Throwable cause) {
        super(msg, null, null, cause);
    }

    /**
     * TODO DOCUMENT ME
     * @param msg
     * @param clusterAlias
     * @param fatalForCCS
     * @param cause
     */
    public RemoteTransportException(String msg, String clusterAlias, boolean fatalForCCS, Throwable cause) {
        super(msg, null, null, cause);
        this.clusterAlias = clusterAlias;
        this.fatalForCCS = fatalForCCS;
    }

    public RemoteTransportException(String name, TransportAddress address, String action, Throwable cause) {
        super(name, address, action, cause);
    }

    public RemoteTransportException(String name, InetSocketAddress address, String action, Throwable cause) {
        super(name, address, action, null, cause);
    }

    public RemoteTransportException(StreamInput in) throws IOException {
        super(in);
    }

    public String getClusterAlias() {
        return clusterAlias;
    }

    public boolean isFatalForCCS() {
        return fatalForCCS;
    }

    @Override
    public Throwable fillInStackTrace() {
        // no need for stack trace here, we always have cause
        return this;
    }
}
