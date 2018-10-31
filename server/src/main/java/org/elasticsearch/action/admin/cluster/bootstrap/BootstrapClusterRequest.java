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
package org.elasticsearch.action.admin.cluster.bootstrap;

import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;

public class BootstrapClusterRequest extends ActionRequest {
    private BootstrapConfiguration bootstrapConfiguration;

    public BootstrapClusterRequest setBootstrapConfiguration(BootstrapConfiguration bootstrapConfiguration) {
        this.bootstrapConfiguration = bootstrapConfiguration;
        return this;
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public BootstrapConfiguration getBootstrapConfiguration() {
        return bootstrapConfiguration;
    }

    @Override
    public void readFrom(StreamInput in) throws IOException {
        super.readFrom(in);
        bootstrapConfiguration = new BootstrapConfiguration(in);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        bootstrapConfiguration.writeTo(out);
    }
}
