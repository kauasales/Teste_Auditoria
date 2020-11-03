/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action.saml;

import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;

import static org.hamcrest.Matchers.containsString;

public class SamlSPMetadataRequestTests  extends ESTestCase {

    public void testValidateFailsWhenRealmNotSet() {
        final SamlSPMetadataRequest samlSPMetadataRequest = new SamlSPMetadataRequest();
        final ActionRequestValidationException validationException = samlSPMetadataRequest.validate();
        assertThat(validationException.getMessage(), containsString("realm may not be empty"));
    }

    public void testValidateSerialization()  throws IOException {
        final SamlSPMetadataRequest samlSPMetadataRequest = new SamlSPMetadataRequest();
        samlSPMetadataRequest.setRealmName("saml1");
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            samlSPMetadataRequest.writeTo(out);
            try (StreamInput in = out.bytes().streamInput()) {
                final SamlSPMetadataRequest serialized = new SamlSPMetadataRequest(in);
                assertEquals(samlSPMetadataRequest.getRealmName(), serialized.getRealmName());
            }
        }
    }

    public void testValidateToString() {
        final SamlSPMetadataRequest samlSPMetadataRequest = new SamlSPMetadataRequest();
        samlSPMetadataRequest.setRealmName("saml1");
        assertThat(samlSPMetadataRequest.toString(), containsString("{realmName=saml1}"));
    }
}
