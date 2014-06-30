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

package org.elasticsearch.search.aggregations;

import org.elasticsearch.ElasticsearchIllegalStateException;
import org.elasticsearch.common.lease.Releasable;

import java.io.IOException;

/**
 * Abstraction for implementations that record a "collect" stream for subsequent play-back
 */
public abstract class RecordingBucketCollector extends BucketCollector implements Releasable {

    /**
     * Replay a previously executed set of calls to the {@link #collect(int, long)} method
     * @param collector the object which will be called to handle the playback
     * @throws IOException
     */
    public abstract void replayCollection(BucketCollector collector) throws IOException;

    @Override
    public void gatherAnalysis(BucketAnalysisCollector analysisCollector, long bucketOrdinal) {
        throw new ElasticsearchIllegalStateException("gatherAnalysis not supported");
    }    
}
