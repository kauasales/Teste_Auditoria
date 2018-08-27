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

package org.elasticsearch.client.indexlifecycle;

import org.elasticsearch.test.ESTestCase;

public class DeleteLifecycleRequestTests extends ESTestCase {

    private DeleteLifecycleRequest createTestInstance() {
        return new DeleteLifecycleRequest(randomAlphaOfLengthBetween(2, 20));
    }

    public void testValidate() {
        DeleteLifecycleRequest req = createTestInstance();
        assertTrue(req.validate() == null || req.validate().validationErrors().size() == 0);

    }

    public void testValidationFailure() {
        try {
            DeleteLifecycleRequest req = new DeleteLifecycleRequest(randomFrom("", null));
            fail("should not be able to create a DeleteLifecycleRequest with null lifecycle name");
        } catch (IllegalArgumentException exception) {
            // ok
        }
    }
}
