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

import org.elasticsearch.Version;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.bytes.CompositeBytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.ReleasableBytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.Set;

public abstract class NetworkMessage implements Writeable {

    protected final ThreadPool threadPool;
    protected final Version version;
    protected final long requestId;
    protected final Writeable message;
    protected final boolean compress;
    protected byte status;

    NetworkMessage(ThreadPool threadPool, Version version, byte status, long requestId, Writeable message, boolean compress) {
        this.threadPool = threadPool;
        this.version = version;
        this.requestId = requestId;
        this.message = message;
        this.status = status;
        this.compress = compress && canCompress(message);
    }

    BytesReference serialize(BytesStreamOutput bytesStream) throws IOException {
        if (compress) {
            status = TransportStatus.setCompress(status);
        }
        bytesStream.setVersion(version);
        bytesStream.skip(TcpHeader.HEADER_SIZE);

        final CompressibleBytesOutputStream stream = new CompressibleBytesOutputStream(bytesStream, compress);
        stream.setVersion(version);
        threadPool.getThreadContext().writeTo(stream);
        writeTo(stream);
        BytesReference reference = writeMessage(stream);
        bytesStream.seek(0);
        TcpHeader.writeHeader(bytesStream, requestId, status, version, reference.length() - 6);
        return reference;
    }

    private BytesReference writeMessage(CompressibleBytesOutputStream stream) throws IOException {
        final BytesReference zeroCopyBuffer;
        if (message instanceof BytesTransportRequest) {
            BytesTransportRequest bRequest = (BytesTransportRequest) message;
            bRequest.writeThin(stream);
            zeroCopyBuffer = bRequest.bytes;
        } else if (message instanceof RemoteTransportException) {
            stream.writeException((RemoteTransportException) message);
            zeroCopyBuffer = BytesArray.EMPTY;
        } else {
            message.writeTo(stream);
            zeroCopyBuffer = BytesArray.EMPTY;
        }
        // we have to call materializeBytes() here before accessing the bytes. A CompressibleBytesOutputStream
        // might be implementing compression. And materializeBytes() ensures that some marker bytes (EOS marker)
        // are written. Otherwise we barf on the decompressing end when we read past EOF on purpose in the
        // #validateRequest method. this might be a problem in deflate after all but it's important to write
        // the marker bytes.
        final BytesReference message = stream.materializeBytes();
        if (zeroCopyBuffer.length() == 0) {
            return message;
        } else {
            return new CompositeBytesReference(message, zeroCopyBuffer);
        }
    }

    static class Request extends NetworkMessage {

        private final String[] features;
        private final String action;

        Request(ThreadPool threadPool, String[] features, byte status, Writeable message, Version version, String action, long requestId,
                boolean compress) {
            super(threadPool, version, status, requestId, message, compress);
            this.features = features;
            this.action = action;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            if (version.onOrAfter(Version.V_6_3_0)) {
                out.writeStringArray(features);
            }
            out.writeString(action);
        }
    }

    static class Response extends NetworkMessage {

        private final Set<String> features;

        Response(ThreadPool threadPool, Set<String> features, byte status, Writeable message, Version version, long requestId,
                 boolean compress) {
            super(threadPool, version, status, requestId, message, compress);
            this.features = features;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.setFeatures(features);
        }
    }

    private static boolean canCompress(Writeable message) {
        return message instanceof BytesTransportRequest == false;
    }
}
