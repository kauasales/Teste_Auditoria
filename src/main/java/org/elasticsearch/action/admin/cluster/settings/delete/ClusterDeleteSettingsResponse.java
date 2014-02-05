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

package org.elasticsearch.action.admin.cluster.settings.delete;

import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;

import java.io.IOException;

/**
 * A response for a cluster delete settings action.
 */
public class ClusterDeleteSettingsResponse extends AcknowledgedResponse {

    Settings transientSettings;
    Settings persistentSettings;

    ClusterDeleteSettingsResponse() {
        this.persistentSettings = ImmutableSettings.EMPTY;
        this.transientSettings = ImmutableSettings.EMPTY;
    }

    ClusterDeleteSettingsResponse(boolean acknowledged, Settings transientSettings, Settings persistentSettings) {
        super(acknowledged);
        this.persistentSettings = persistentSettings;
        this.transientSettings = transientSettings;
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        transientSettings = ImmutableSettings.readSettingsFromStream(in);
        persistentSettings = ImmutableSettings.readSettingsFromStream(in);
        readAcknowledged(in);
    }

    public Settings getTransientSettings() {
        return transientSettings;
    }

    public Settings getPersistentSettings() {
        return persistentSettings;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        ImmutableSettings.writeSettingsToStream(transientSettings, out);
        ImmutableSettings.writeSettingsToStream(persistentSettings, out);
        writeAcknowledged(out);
    }
}
