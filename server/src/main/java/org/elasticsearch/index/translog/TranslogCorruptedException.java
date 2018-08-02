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

package org.elasticsearch.index.translog;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.index.translog.source.TranslogSource;

import java.io.IOException;

public class TranslogCorruptedException extends ElasticsearchException {
    public TranslogCorruptedException(TranslogSource source, String details) {
        super(corruptedMessage(source, details));
    }

    public TranslogCorruptedException(TranslogSource source, String details, Throwable cause) {
        super(corruptedMessage(source, details), cause);
    }

    private static String corruptedMessage(TranslogSource source, String details) {
        return "translog from source [" + source + "] is corrupted, " + details;
    }

    public TranslogCorruptedException(StreamInput in) throws IOException {
        super(in);
    }
}
