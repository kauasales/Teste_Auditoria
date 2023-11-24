/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authc.jwt;

import org.elasticsearch.common.settings.SettingsException;
import org.elasticsearch.xpack.core.security.authc.RealmSettings;
import org.elasticsearch.xpack.core.security.authc.jwt.JwtRealmSettings;

import java.text.ParseException;

import static org.hamcrest.Matchers.containsString;

public class JwtAuthenticatorAccessTokenTypeTests extends JwtAuthenticatorTests {

    @Override
    protected JwtRealmSettings.TokenType getTokenType() {
        return JwtRealmSettings.TokenType.ACCESS_TOKEN;
    }

    public void testSubjectIsRequired() throws ParseException {
        final IllegalArgumentException e = doTestSubjectIsRequired(buildJwtAuthenticator());
        if (fallbackSub != null) {
            assertThat(e.getMessage(), containsString("missing required string claim [" + fallbackSub + " (fallback of sub)]"));
        }
    }

    public void testAccessTokenTypeMandatesAllowedSubjects() {
        allowedSubject = null;
        allowedSubjectPattern = null;
        final SettingsException e = expectThrows(SettingsException.class, () -> buildJwtAuthenticator());
        assertThat(
            e.getMessage(),
            containsString(
                "One of either ["
                    + RealmSettings.getFullSettingKey(realmName, JwtRealmSettings.ALLOWED_SUBJECTS)
                    + "] or ["
                    + RealmSettings.getFullSettingKey(realmName, JwtRealmSettings.ALLOWED_SUBJECT_PATTERNS)
                    + "] must be specified."
            )
        );
    }

    public void testInvalidIssuerIsCheckedBeforeAlgorithm() throws ParseException {
        doTestInvalidIssuerIsCheckedBeforeAlgorithm(buildJwtAuthenticator());
    }
}
