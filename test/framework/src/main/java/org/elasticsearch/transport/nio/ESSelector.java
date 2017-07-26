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

package org.elasticsearch.transport.nio;

import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.transport.nio.channel.NioChannel;

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.Selector;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * This is a basic selector abstraction used by {@link org.elasticsearch.transport.nio.NioTransport}. This
 * selector wraps a raw nio {@link Selector}. When you call {@link #runLoop()}, the selector will run until
 * {@link #close()} is called. This instance handles closing of channels. Users should call
 * {@link #queueChannelClose(NioChannel)} to schedule a channel for close by this selector.
 * <p>
 * Children of this class should implement the specific {@link #doSelect(int)} and {@link #cleanup()}
 * functionality.
 */
public abstract class ESSelector implements Closeable {

    final Selector selector;
    final ConcurrentLinkedQueue<NioChannel> channelsToClose = new ConcurrentLinkedQueue<>();

    private final EventHandler eventHandler;
    private final ReentrantLock runLock = new ReentrantLock();
    private final CountDownLatch exitedLoop = new CountDownLatch(1);
    private final AtomicBoolean isClosed = new AtomicBoolean(false);
    private final PlainActionFuture<Boolean> isRunningFuture = PlainActionFuture.newFuture();
    private final Set<NioChannel> registeredChannels = Collections.newSetFromMap(new ConcurrentHashMap<NioChannel, Boolean>());
    private volatile Thread thread;

    ESSelector(EventHandler eventHandler) throws IOException {
        this(eventHandler, Selector.open());
    }

    ESSelector(EventHandler eventHandler, Selector selector) throws IOException {
        this.eventHandler = eventHandler;
        this.selector = selector;
    }

    /**
     * Starts this selector. The selector will run until {@link #close()} is called.
     */
    public void runLoop() {
        if (runLock.tryLock()) {
            isRunningFuture.onResponse(true);
            try {
                setThread();
                while (isOpen()) {
                    singleLoop();
                }
            } finally {
                try {
                    cleanupAndCloseChannels();
                } finally {
                    try {
                        selector.close();
                    } catch (IOException e) {
                        eventHandler.closeSelectorException(e);
                    } finally {
                        runLock.unlock();
                        exitedLoop.countDown();
                    }
                }
            }
        } else {
            throw new IllegalStateException("selector is already running");
        }
    }

    void singleLoop() {
        try {
            closePendingChannels();
            doSelect(300);
        } catch (ClosedSelectorException e) {
            if (isOpen()) {
                throw e;
            }
        } catch (IOException e) {
            eventHandler.selectException(e);
        } catch (Exception e) {
            eventHandler.uncaughtException(e);
        }
    }

    void cleanupAndCloseChannels() {
        cleanup();
        channelsToClose.addAll(registeredChannels);
        closePendingChannels();
    }

    /**
     * Should implement the specific select logic. This will be called once per {@link #singleLoop()}
     *
     * @param timeout to pass to the raw select operation
     * @throws IOException             thrown by the raw select operation
     * @throws ClosedSelectorException thrown if the raw selector is closed
     */
    abstract void doSelect(int timeout) throws IOException, ClosedSelectorException;

    /**
     * Called once as the selector is being closed.
     */
    abstract void cleanup();

    void setThread() {
        thread = Thread.currentThread();
    }

    public boolean isOnCurrentThread() {
        return Thread.currentThread() == thread;
    }

    void wakeup() {
        // TODO: Do we need the wakeup optimizations that some other libraries use?
        selector.wakeup();
    }

    public Set<NioChannel> getRegisteredChannels() {
        return registeredChannels;
    }

    public void addRegisteredChannel(NioChannel channel) {
        assert registeredChannels.contains(channel) == false : "Should only register channel once";
        registeredChannels.add(channel);
    }

    public void removeRegisteredChannel(NioChannel channel) {
        registeredChannels.remove(channel);
    }

    @Override
    public void close() throws IOException {
        if (isClosed.compareAndSet(false, true)) {
            wakeup();
            if (isRunning()) {
                try {
                    exitedLoop.await();
                } catch (InterruptedException e) {
                    eventHandler.uncaughtException(e);
                }
            }
        }
    }

    public void queueChannelClose(NioChannel channel) {
        assert channel.getSelector() == this : "Must schedule a channel for closure with its selector";
        channelsToClose.offer(channel);
        ensureSelectorOpenForEnqueuing(channelsToClose, channel);
        wakeup();
    }

    public Selector rawSelector() {
        return selector;
    }

    public boolean isOpen() {
        return isClosed.get() == false;
    }

    public boolean isRunning() {
        return runLock.isLocked();
    }

    public PlainActionFuture<Boolean> isRunningFuture() {
        return isRunningFuture;
    }

    /**
     * This is a convenience method to be called after some object (normally channels) are enqueued with this
     * selector. This method will check if the selector is still open. If it is open, normal operation can
     * proceed.
     *
     * If the selector is closed, then we attempt to remove the object from the queue. If the removal
     * succeeds then we throw an {@link IllegalStateException} indicating that normal operation failed. If
     * the object cannot be removed from the queue, then the object has already been handled by the selector
     * and operation can proceed normally.
     *
     * If this method is called from the selector thread, we will not throw an exception as the selector
     * thread can manipulate its queues internally even if it is no longer open.
     *
     * @param queue the queue to which the object was added
     * @param objectAdded the objected added
     * @param <O> the object type
     */
    <O> void ensureSelectorOpenForEnqueuing(ConcurrentLinkedQueue<O> queue, O objectAdded) {
        if (isOpen() == false && isOnCurrentThread() == false) {
            if (queue.remove(objectAdded)) {
                throw new IllegalStateException("selector is already closed");
            }
        }
    }

    private void closePendingChannels() {
        NioChannel channel;
        while ((channel = channelsToClose.poll()) != null) {
            eventHandler.handleClose(channel);
        }
    }
}
