package org.elasticsearch.transport.netty;

import org.elasticsearch.common.transport.WrongPortException;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.monitor.jvm.JvmInfo;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.FrameDecoder;
import org.jboss.netty.handler.codec.frame.TooLongFrameException;

import java.io.StreamCorruptedException;

/**
 */
public class SizeHeaderFrameDecoder extends FrameDecoder {

    private static final long NINETY_PER_HEAP_SIZE = (long) (JvmInfo.jvmInfo().mem().heapMax().bytes() * 0.9);

    @Override
    protected Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        if (buffer.readableBytes() < 4) {
            return null;
        }

        int dataLen = buffer.getInt(buffer.readerIndex());
        
        // check if we received HTTP GET or POST accidently
        // 'G', 'E', 'T', ' ' = 0x47, 0x45, 0x54, 0x20 = 1195725856
        // 'P', 'O', 'S', 'T' = 0x50, 0x4F, 0x53, 0x54 = 1347375956
        // 'P', 'U', 'T', ' ' = 0x50, 0x55, 0x54, 0x20 = 1347769376
        // 'D', 'E', 'L', 'E' = 0x44, 0x45, 0x4c, 0x45 = 1145392197
        if (dataLen == 1347375956  || dataLen == 1347769376 || dataLen == 1145392197 || dataLen == 1195725856) {
            throw new WrongPortException("sorry, this port is not for HTTP requests\n");
        }        
        if (dataLen <= 0) {
            throw new StreamCorruptedException("invalid data length: " + dataLen);
        }
        // safety against too large frames being sent
        if (dataLen > NINETY_PER_HEAP_SIZE) {
            throw new TooLongFrameException(
                    "transport content length received [" + new ByteSizeValue(dataLen) + "] exceeded [" + new ByteSizeValue(NINETY_PER_HEAP_SIZE) + "]");
        }

        if (buffer.readableBytes() < dataLen + 4) {
            return null;
        }
        buffer.skipBytes(4);
        return buffer;
    }
}