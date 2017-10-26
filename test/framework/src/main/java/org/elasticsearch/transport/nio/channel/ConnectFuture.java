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

package org.elasticsearch.transport.nio.channel;

import org.elasticsearch.transport.PlainChannelFuture;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class ConnectFuture extends PlainChannelFuture<NioChannel> {

    public ConnectFuture(NioChannel nioChannel) {
        super(nioChannel);
    }

    public boolean awaitConnectionComplete(long timeout, TimeUnit unit) {
        try {
            super.get(timeout, unit);
            return true;
        } catch (ExecutionException | TimeoutException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    public Exception getException() {
        if (isDone()) {
            try {
                // Get should always return without blocking as we already checked 'isDone'
                // We are calling 'get' here in order to throw the ExecutionException
                super.get();
                return null;
            } catch (ExecutionException e) {
                // We only make a public setters for IOException or RuntimeException
                return (Exception) e.getCause();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted", e);
            }
        } else {
            return null;
        }
    }

    public boolean isConnectComplete() {
        return isConnectComplete0();
    }

    public boolean connectFailed() {
        return getException() != null;
    }

    void setConnectionComplete() {
        onResponse(channel());
    }

    void setConnectionFailed(IOException e) {
        setException(e);
    }

    void setConnectionFailed(RuntimeException e) {
        setException(e);
    }

    private boolean isConnectComplete0() {
        if (isDone()) {
            try {
                // Get should always return without blocking as we already checked 'isDone'
                return super.get(0, TimeUnit.NANOSECONDS) != null;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted", e);
            } catch (ExecutionException e) {
                return false;
            } catch (TimeoutException e) {
                throw new AssertionError("This should never happen as we only call get() after isDone() is true.");
            }
        } else {
            return false;
        }
    }
}
