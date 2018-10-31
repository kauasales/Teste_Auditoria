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

import org.elasticsearch.action.admin.cluster.bootstrap.BootstrapConfiguration.NodeDescription;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;
import java.util.Collections;

import static org.elasticsearch.common.io.stream.Streamable.newWriteableReader;
import static org.hamcrest.Matchers.equalTo;

public class BootstrapClusterRequestTests extends ESTestCase {

    public void testSerialization() throws IOException {
        final BootstrapConfiguration bootstrapConfiguration
            = new BootstrapConfiguration(Collections.singletonList(new NodeDescription(null, randomAlphaOfLength(10))));
        final BootstrapClusterRequest original = new BootstrapClusterRequest().setBootstrapConfiguration(bootstrapConfiguration);
        assertNull(original.validate());
        final BootstrapClusterRequest deserialized
            = copyWriteable(original, writableRegistry(), newWriteableReader(BootstrapClusterRequest::new));
        assertThat(deserialized.getBootstrapConfiguration(), equalTo(bootstrapConfiguration));
    }
}
