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
package org.elasticsearch.transport;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.concurrent.CompletableContext;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicReference;

public class FakeTcpChannel implements TcpChannel {

    private final String profile;
    private final AtomicReference<BytesReference> messageCaptor;
    private final CompletableContext<Void> closeContext = new CompletableContext<>();

    public FakeTcpChannel() {
        this("profile", new AtomicReference<>());
    }

    public FakeTcpChannel(AtomicReference<BytesReference> messageCaptor) {
        this("profile", messageCaptor);
    }


    public FakeTcpChannel(String profile, AtomicReference<BytesReference> messageCaptor) {
        this.profile = profile;
        this.messageCaptor = messageCaptor;
    }


    @Override
    public String getProfile() {
        return profile;
    }

    @Override
    public void setSoLinger(int value) throws IOException {

    }

    @Override
    public InetSocketAddress getLocalAddress() {
        return null;
    }

    @Override
    public InetSocketAddress getRemoteAddress() {
        return null;
    }

    @Override
    public void sendMessage(BytesReference reference, ActionListener<Void> listener) {
        messageCaptor.set(reference);
    }

    @Override
    public void addConnectListener(ActionListener<Void> listener) {

    }

    @Override
    public void close() {
        closeContext.complete(null);
    }

    @Override
    public void addCloseListener(ActionListener<Void> listener) {
        closeContext.addListener(ActionListener.toBiConsumer(listener));
    }

    @Override
    public boolean isOpen() {
        return closeContext.isDone() == false;
    }
}
