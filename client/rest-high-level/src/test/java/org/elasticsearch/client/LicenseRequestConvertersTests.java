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

package org.elasticsearch.client;

import org.apache.http.client.methods.HttpPost;
import org.elasticsearch.client.license.StartTrialRequest;
import org.elasticsearch.test.ESTestCase;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;


public class LicenseRequestConvertersTests extends ESTestCase {

    public void testStartTrial() {
        final boolean acknowledge = randomBoolean();
        final String licenseType = randomBoolean()
            ? randomAlphaOfLengthBetween(3, 10)
            : null;

        final Map<String, String> expectedParams = new HashMap<>();
        expectedParams.put("acknowledge", Boolean.toString(acknowledge));
        if (licenseType != null) {
            expectedParams.put("type", licenseType);
        }

        final StartTrialRequest hlrcRequest = new StartTrialRequest(acknowledge, licenseType);
        final Request restRequest = LicenseRequestConverters.startTrial(hlrcRequest);

        assertThat(restRequest.getMethod(), equalTo(HttpPost.METHOD_NAME));
        assertThat(restRequest.getEndpoint(), equalTo("/_xpack/license/start_trial"));
        assertThat(restRequest.getParameters(), equalTo(expectedParams));
        assertThat(restRequest.getEntity(), nullValue());
    }
}
