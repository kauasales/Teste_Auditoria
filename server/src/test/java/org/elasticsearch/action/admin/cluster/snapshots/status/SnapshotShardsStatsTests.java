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

package org.elasticsearch.action.admin.cluster.snapshots.status;

import java.io.IOException;

import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentParserUtils;
import org.elasticsearch.test.AbstractXContentTestCase;

public class SnapshotShardsStatsTests extends AbstractXContentTestCase<SnapshotShardsStats> {

    @Override
    protected SnapshotShardsStats createTestInstance() {
        int initializingShards = randomInt();
        int startedShards = randomInt();
        int finalizingShards = randomInt();
        int doneShards = randomInt();
        int failedShards = randomInt();
        int totalShards = randomInt();
        return new SnapshotShardsStats(initializingShards, startedShards, finalizingShards, doneShards, failedShards, totalShards);
    }

    @Override
    protected SnapshotShardsStats doParseInstance(XContentParser parser) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser::getTokenLocation);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.nextToken(), parser::getTokenLocation);
        SnapshotShardsStats stats = SnapshotShardsStats.fromXContent(parser);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, parser.nextToken(), parser::getTokenLocation);
        return stats;
    }

    @Override
    protected boolean supportsUnknownFields() {
        return false;
    }
}
