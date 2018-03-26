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

import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.test.ESTestCase;
import org.junit.Before;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.isNull;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class BytesChannelContextTests extends ESTestCase {

    private SocketChannelContext.ReadConsumer readConsumer;
    private SocketChannelContext.FlushProducer writeProducer;
    private NioSocketChannel channel;
    private SocketChannel rawChannel;
    private BytesChannelContext context;
    private InboundChannelBuffer channelBuffer;
    private SocketSelector selector;
    private Consumer<Exception> exceptionHandler;
    private BiConsumer<Void, Throwable> listener;
    private int messageLength;

    @Before
    @SuppressWarnings("unchecked")
    public void init() {
        readConsumer = mock(SocketChannelContext.ReadConsumer.class);
        writeProducer = mock(SocketChannelContext.FlushProducer.class);

        messageLength = randomInt(96) + 20;
        selector = mock(SocketSelector.class);
        listener = mock(BiConsumer.class);
        channel = mock(NioSocketChannel.class);
        rawChannel = mock(SocketChannel.class);
        channelBuffer = InboundChannelBuffer.allocatingInstance();
        exceptionHandler = mock(Consumer.class);
        when(channel.getRawChannel()).thenReturn(rawChannel);
        context = new BytesChannelContext(channel, selector, exceptionHandler, readConsumer, writeProducer, channelBuffer);

        when(selector.isOnCurrentThread()).thenReturn(true);
    }

    public void testSuccessfulRead() throws IOException {
        byte[] bytes = createMessage(messageLength);

        when(rawChannel.read(any(ByteBuffer[].class), anyInt(), anyInt())).thenAnswer(invocationOnMock -> {
            ByteBuffer[] buffers = (ByteBuffer[]) invocationOnMock.getArguments()[0];
            buffers[0].put(bytes);
            return bytes.length;
        });

        when(readConsumer.consumeReads(channelBuffer)).thenReturn(messageLength, 0);

        assertEquals(messageLength, context.read());

        assertEquals(0, channelBuffer.getIndex());
        assertEquals(BigArrays.BYTE_PAGE_SIZE - bytes.length, channelBuffer.getCapacity());
        verify(readConsumer, times(1)).consumeReads(channelBuffer);
    }

    public void testMultipleReadsConsumed() throws IOException {
        byte[] bytes = createMessage(messageLength * 2);

        when(rawChannel.read(any(ByteBuffer[].class), anyInt(), anyInt())).thenAnswer(invocationOnMock -> {
            ByteBuffer[] buffers = (ByteBuffer[]) invocationOnMock.getArguments()[0];
            buffers[0].put(bytes);
            return bytes.length;
        });

        when(readConsumer.consumeReads(channelBuffer)).thenReturn(messageLength, messageLength, 0);

        assertEquals(bytes.length, context.read());

        assertEquals(0, channelBuffer.getIndex());
        assertEquals(BigArrays.BYTE_PAGE_SIZE - bytes.length, channelBuffer.getCapacity());
        verify(readConsumer, times(2)).consumeReads(channelBuffer);
    }

    public void testPartialRead() throws IOException {
        byte[] bytes = createMessage(messageLength);

        when(rawChannel.read(any(ByteBuffer[].class), anyInt(), anyInt())).thenAnswer(invocationOnMock -> {
            ByteBuffer[] buffers = (ByteBuffer[]) invocationOnMock.getArguments()[0];
            buffers[0].put(bytes);
            return bytes.length;
        });


        when(readConsumer.consumeReads(channelBuffer)).thenReturn(0);

        assertEquals(messageLength, context.read());

        assertEquals(bytes.length, channelBuffer.getIndex());
        verify(readConsumer, times(1)).consumeReads(channelBuffer);

        when(readConsumer.consumeReads(channelBuffer)).thenReturn(messageLength * 2, 0);

        assertEquals(messageLength, context.read());

        assertEquals(0, channelBuffer.getIndex());
        assertEquals(BigArrays.BYTE_PAGE_SIZE - (bytes.length * 2), channelBuffer.getCapacity());
        verify(readConsumer, times(2)).consumeReads(channelBuffer);
    }

    public void testReadThrowsIOException() throws IOException {
        IOException ioException = new IOException();
        when(rawChannel.read(any(ByteBuffer[].class), anyInt(), anyInt())).thenThrow(ioException);

        IOException ex = expectThrows(IOException.class, () -> context.read());
        assertSame(ioException, ex);
    }

    public void testReadThrowsIOExceptionMeansReadyForClose() throws IOException {
        when(rawChannel.read(any(ByteBuffer[].class), anyInt(), anyInt())).thenThrow(new IOException());

        assertFalse(context.selectorShouldClose());
        expectThrows(IOException.class, () -> context.read());
        assertTrue(context.selectorShouldClose());
    }

    public void testReadLessThanZeroMeansReadyForClose() throws IOException {
        when(rawChannel.read(any(ByteBuffer[].class), anyInt(), anyInt())).thenReturn(-1L);

        assertEquals(0, context.read());

        assertTrue(context.selectorShouldClose());
    }

    @SuppressWarnings("unchecked")
    public void testCloseClosesChannelBuffer() throws IOException {
        try (SocketChannel realChannel = SocketChannel.open()) {
            when(channel.getRawChannel()).thenReturn(realChannel);
            when(channel.isOpen()).thenReturn(true);
            Runnable closer = mock(Runnable.class);
            Supplier<InboundChannelBuffer.Page> pageSupplier = () -> new InboundChannelBuffer.Page(ByteBuffer.allocate(1 << 14), closer);
            InboundChannelBuffer buffer = new InboundChannelBuffer(pageSupplier);
            buffer.ensureCapacity(1);
            BytesChannelContext context = new BytesChannelContext(channel, selector, exceptionHandler, readConsumer, writeProducer, buffer);
            context.closeFromSelector();
            verify(closer).run();
        }
    }

    public void testCloseClosesWriteProducer() throws IOException {
        try (SocketChannel realChannel = SocketChannel.open()) {
            when(channel.getRawChannel()).thenReturn(realChannel);
            when(channel.isOpen()).thenReturn(true);
            InboundChannelBuffer buffer = InboundChannelBuffer.allocatingInstance();
            BytesChannelContext context = new BytesChannelContext(channel, selector, exceptionHandler, readConsumer, writeProducer, buffer);
            context.closeFromSelector();
            verify(writeProducer).close();
        }
    }

    public void testWriteFailsIfClosing() {
        context.closeChannel();

        ByteBuffer[] buffers = {ByteBuffer.wrap(createMessage(10))};
        context.sendMessage(buffers, listener);

        verify(listener).accept(isNull(Void.class), any(ClosedChannelException.class));
    }

    public void testSendMessageFromDifferentThreadIsQueuedWithSelector() throws Exception {
        ArgumentCaptor<WriteOperation> writeOpCaptor = ArgumentCaptor.forClass(WriteOperation.class);

        when(selector.isOnCurrentThread()).thenReturn(false);

        ByteBuffer[] buffers = {ByteBuffer.wrap(createMessage(10))};
        context.sendMessage(buffers, listener);

        verify(selector).queueWrite(writeOpCaptor.capture());
        WriteOperation writeOp = writeOpCaptor.getValue();

        assertSame(listener, writeOp.getListener());
        assertSame(context, writeOp.getChannel());
        assertEquals(buffers, writeOp.getObject());
    }

    public void testSendMessageFromSameThreadIsQueuedInChannel() {
        ArgumentCaptor<WriteOperation> writeOpCaptor = ArgumentCaptor.forClass(WriteOperation.class);

        ByteBuffer[] buffers = {ByteBuffer.wrap(createMessage(10))};
        context.sendMessage(buffers, listener);

        verify(selector).queueWriteInChannelBuffer(writeOpCaptor.capture());
        WriteOperation writeOp = writeOpCaptor.getValue();

        assertSame(listener, writeOp.getListener());
        assertSame(context, writeOp.getChannel());
        assertSame(buffers, writeOp.getObject());
    }

    public void testWriteIsQueuedInChannel() {
        assertFalse(context.hasQueuedWriteOps());

        ByteBuffer[] buffer = {ByteBuffer.allocate(10)};
        WriteOperation writeOperation = new WriteOperation(context, buffer, listener);
        when(writeProducer.pollFlushOperation()).thenReturn(mock(FlushOperation.class));
        context.queueWriteOperation(writeOperation);

        verify(writeProducer).produceWrites(writeOperation);
        assertTrue(context.hasQueuedWriteOps());
    }

    @SuppressWarnings("unchecked")
    public void testFlushOpsClearedOnClose() throws Exception {
        try (SocketChannel realChannel = SocketChannel.open()) {
            when(channel.getRawChannel()).thenReturn(realChannel);
            context = new BytesChannelContext(channel, selector, exceptionHandler, readConsumer, writeProducer, channelBuffer);

            assertFalse(context.hasQueuedWriteOps());

            ByteBuffer[] buffer = {ByteBuffer.allocate(10)};
            when(writeProducer.pollFlushOperation()).thenReturn(new FlushOperation(buffer, listener));
            context.queueWriteOperation(mock(WriteOperation.class));

            assertTrue(context.hasQueuedWriteOps());

            when(channel.isOpen()).thenReturn(true);
            context.closeFromSelector();

            verify(selector).executeFailedListener(same(listener), any(ClosedChannelException.class));

            assertFalse(context.hasQueuedWriteOps());
        }
    }

    public void testQueuedWriteIsFlushedInFlushCall() throws Exception {
        assertFalse(context.hasQueuedWriteOps());

        ByteBuffer[] buffers = {ByteBuffer.allocate(10)};
        FlushOperation flushOperation = mock(FlushOperation.class);
        when(writeProducer.pollFlushOperation()).thenReturn(flushOperation, null);
        context.queueWriteOperation(mock(WriteOperation.class));

        assertTrue(context.hasQueuedWriteOps());

        when(flushOperation.getBuffersToWrite()).thenReturn(buffers);
        when(flushOperation.isFullyFlushed()).thenReturn(true);
        when(flushOperation.getListener()).thenReturn(listener);
        context.flushChannel();

        verify(rawChannel).write(buffers, 0, buffers.length);
        verify(selector).executeListener(listener, null);
        assertFalse(context.hasQueuedWriteOps());
    }

    public void testPartialFlush() throws IOException {
        assertFalse(context.hasQueuedWriteOps());
        FlushOperation flushOperation = mock(FlushOperation.class);
        when(writeProducer.pollFlushOperation()).thenReturn(flushOperation);
        context.queueWriteOperation(mock(WriteOperation.class));
        assertTrue(context.hasQueuedWriteOps());

        when(flushOperation.isFullyFlushed()).thenReturn(false);
        when(flushOperation.getBuffersToWrite()).thenReturn(new ByteBuffer[0]);
        context.flushChannel();

        verify(listener, times(0)).accept(null, null);
        assertTrue(context.hasQueuedWriteOps());
    }

    @SuppressWarnings("unchecked")
    public void testMultipleWritesPartialFlushes() throws IOException {
        assertFalse(context.hasQueuedWriteOps());

        BiConsumer<Void, Throwable> listener2 = mock(BiConsumer.class);
        FlushOperation flushOperation1 = mock(FlushOperation.class);
        FlushOperation flushOperation2 = mock(FlushOperation.class);
        when(flushOperation1.getBuffersToWrite()).thenReturn(new ByteBuffer[0]);
        when(flushOperation2.getBuffersToWrite()).thenReturn(new ByteBuffer[0]);
        when(flushOperation1.getListener()).thenReturn(listener);
        when(flushOperation2.getListener()).thenReturn(listener2);

        when(writeProducer.pollFlushOperation()).thenReturn(flushOperation1, flushOperation2, null);
        context.queueWriteOperation(mock(WriteOperation.class));
        context.queueWriteOperation(mock(WriteOperation.class));

        assertTrue(context.hasQueuedWriteOps());

        when(flushOperation1.isFullyFlushed()).thenReturn(true);
        when(flushOperation2.isFullyFlushed()).thenReturn(false);
        context.flushChannel();

        verify(selector).executeListener(listener, null);
        verify(listener2, times(0)).accept(null, null);
        assertTrue(context.hasQueuedWriteOps());

        when(flushOperation2.isFullyFlushed()).thenReturn(true);

        context.flushChannel();

        verify(selector).executeListener(listener2, null);
        assertFalse(context.hasQueuedWriteOps());
    }

    public void testWhenIOExceptionThrownListenerIsCalled() throws IOException {
        assertFalse(context.hasQueuedWriteOps());

        ByteBuffer[] buffers = {ByteBuffer.allocate(10)};
        FlushOperation flushOperation = mock(FlushOperation.class);
        when(writeProducer.pollFlushOperation()).thenReturn(flushOperation,null);
        context.queueWriteOperation(mock(WriteOperation.class));

        assertTrue(context.hasQueuedWriteOps());

        IOException exception = new IOException();
        when(flushOperation.getBuffersToWrite()).thenReturn(buffers);
        when(rawChannel.write(buffers, 0, buffers.length)).thenThrow(exception);
        when(flushOperation.getListener()).thenReturn(listener);
        expectThrows(IOException.class, () -> context.flushChannel());

        verify(selector).executeFailedListener(listener, exception);
        assertFalse(context.hasQueuedWriteOps());
    }

    public void testWriteIOExceptionMeansChannelReadyToClose() throws IOException {
        ByteBuffer[] buffers = {ByteBuffer.allocate(10)};
        FlushOperation flushOperation = mock(FlushOperation.class);
        when(writeProducer.pollFlushOperation()).thenReturn(flushOperation);
        context.queueWriteOperation(mock(WriteOperation.class));

        IOException exception = new IOException();
        when(flushOperation.getBuffersToWrite()).thenReturn(buffers);
        when(rawChannel.write(buffers, 0, buffers.length)).thenThrow(exception);

        assertFalse(context.selectorShouldClose());
        expectThrows(IOException.class, () -> context.flushChannel());
        assertTrue(context.selectorShouldClose());
    }

    public void initiateCloseSchedulesCloseWithSelector() {
        context.closeChannel();
        verify(selector).queueChannelClose(channel);
    }

    private static byte[] createMessage(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; ++i) {
            bytes[i] = randomByte();
        }
        return bytes;
    }
}
