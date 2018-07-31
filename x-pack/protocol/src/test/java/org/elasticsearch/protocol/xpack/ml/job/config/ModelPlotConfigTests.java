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
package org.elasticsearch.protocol.xpack.ml.job.config;

import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.test.AbstractXContentTestCase;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class ModelPlotConfigTests extends AbstractXContentTestCase<ModelPlotConfig> {

    public void testConstructorDefaults() {
        assertThat(new ModelPlotConfig().isEnabled(), is(true));
        assertThat(new ModelPlotConfig().getTerms(), is(nullValue()));
    }

    @Override
    protected ModelPlotConfig createTestInstance() {
        return new ModelPlotConfig(randomBoolean(), randomAlphaOfLengthBetween(1, 30));
    }

    @Override
    protected ModelPlotConfig doParseInstance(XContentParser parser) {
        return ModelPlotConfig.PARSER.apply(parser, null);
    }

    @Override
    protected boolean supportsUnknownFields() {
        return true;
    }
}
