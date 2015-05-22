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

package org.elasticsearch.repositories.s3;

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;

/**
 */
public class S3SnapshotRestoreOverHttpTest extends AbstractS3SnapshotRestoreTest {
    @Override
    public Settings nodeSettings(int nodeOrdinal) {
        ImmutableSettings.Builder settings = ImmutableSettings.builder()
                .put(super.nodeSettings(nodeOrdinal))
                .put("cloud.aws.s3.protocol", "http");
        return settings.build();
    }
}
