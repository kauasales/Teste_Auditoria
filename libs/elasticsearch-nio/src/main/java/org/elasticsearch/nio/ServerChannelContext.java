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

package org.elasticsearch.nio;

import java.io.IOException;
import java.nio.channels.ServerSocketChannel;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class ServerChannelContext extends AbstractChannelContext<NioServerSocketChannel> {

    private final NioServerSocketChannel channel;
    private final AcceptingSelector selector;
    private final Consumer<NioSocketChannel> acceptor;
    private final BiConsumer<NioServerSocketChannel, Exception> exceptionHandler;
    private final AtomicBoolean isClosing = new AtomicBoolean(false);
    private final ChannelFactory<?, ?> channelFactory;

    public ServerChannelContext(NioServerSocketChannel channel, ChannelFactory<?, ?> channelFactory, AcceptingSelector selector,
                                Consumer<NioSocketChannel> acceptor, BiConsumer<NioServerSocketChannel, Exception> exceptionHandler) {
        super(channel);
        this.channel = channel;
        this.channelFactory = channelFactory;
        this.selector = selector;
        this.acceptor = acceptor;
        this.exceptionHandler = exceptionHandler;
    }

    public void acceptChannel(NioSocketChannel acceptedChannel) {
        acceptor.accept(acceptedChannel);
    }

    public ChannelFactory<?, ?> getChannelFactory() {
        return channelFactory;
    }

    @Override
    public void closeFromSelector() throws IOException {
        channel.closeFromSelector();
    }

    @Override
    public void closeChannel() {
        if (isClosing.compareAndSet(false, true)) {
            getSelector().queueChannelClose(channel);
        }
    }

    @Override
    public void handleException(Exception e) {
        exceptionHandler.accept(channel, e);
    }

    @Override
    public AcceptingSelector getSelector() {
        return selector;
    }
}
