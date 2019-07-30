/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.Version;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Objects;

import static org.elasticsearch.action.ValidateActions.addValidationError;

/**
 * Request for invalidating API key(s) so that it can no longer be used
 */
public final class InvalidateApiKeyRequest extends ActionRequest {

    private final String realmName;
    private final String userName;
    private final String id;
    private final String name;
    private final boolean myApiKeysOnly;

    public InvalidateApiKeyRequest() {
        this(null, null, null, null, false);
    }

    public InvalidateApiKeyRequest(StreamInput in) throws IOException {
        super(in);
        realmName = in.readOptionalString();
        userName = in.readOptionalString();
        id = in.readOptionalString();
        name = in.readOptionalString();
        if (in.getVersion().onOrAfter(Version.V_7_4_0)) {
            myApiKeysOnly = in.readOptionalBoolean();
        } else {
            myApiKeysOnly = false;
        }
    }

    public InvalidateApiKeyRequest(@Nullable String realmName, @Nullable String userName, @Nullable String id,
                                   @Nullable String name, boolean myApiKeysOnly) {
        this.realmName = realmName;
        this.userName = userName;
        this.id = id;
        this.name = name;
        this.myApiKeysOnly = myApiKeysOnly;
    }

    public String getRealmName() {
        return realmName;
    }

    public String getUserName() {
        return userName;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public boolean myApiKeysOnly() {
        return myApiKeysOnly;
    }

    /**
     * Creates invalidate api key request for given realm name
     *
     * @param realmName realm name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingRealmName(String realmName) {
        return new InvalidateApiKeyRequest(realmName, null, null, null, false);
    }

    /**
     * Creates invalidate API key request for given user name
     *
     * @param userName user name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingUserName(String userName) {
        return new InvalidateApiKeyRequest(null, userName, null, null, false);
    }

    /**
     * Creates invalidate API key request for given realm and user name
     *
     * @param realmName realm name
     * @param userName  user name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingRealmAndUserName(String realmName, String userName) {
        return new InvalidateApiKeyRequest(realmName, userName, null, null, false);
    }

    /**
     * Creates invalidate API key request for given api key id
     *
     * @param id api key id
     * @param myApiKeysOnly set {@code true} if the request is only for the API keys owned by current authenticated user else {@code false}
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingApiKeyId(String id, boolean myApiKeysOnly) {
        return new InvalidateApiKeyRequest(null, null, id, null, myApiKeysOnly);
    }

    /**
     * Creates invalidate api key request for given api key name
     *
     * @param name api key name
     * @param myApiKeysOnly set {@code true} if the request is only for the API keys owned by current authenticated user else {@code false}
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingApiKeyName(String name, boolean myApiKeysOnly) {
        return new InvalidateApiKeyRequest(null, null, null, name, myApiKeysOnly);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (Strings.hasText(realmName) == false && Strings.hasText(userName) == false && Strings.hasText(id) == false
            && Strings.hasText(name) == false) {
            validationException = addValidationError("One of [api key id, api key name, username, realm name] must be specified",
                                                     validationException);
        }
        if (Strings.hasText(id) || Strings.hasText(name)) {
            if (Strings.hasText(realmName) || Strings.hasText(userName)) {
                validationException = addValidationError(
                    "username or realm name must not be specified when the api key id or api key name is specified",
                    validationException);
            }
        }
        if (myApiKeysOnly) {
            if (Strings.hasText(realmName) || Strings.hasText(userName)) {
                validationException = addValidationError(
                    "username or realm name must not be specified when invalidating owned API keys",
                    validationException);
            }
        }
        if (Strings.hasText(id) && Strings.hasText(name)) {
            validationException = addValidationError("only one of [api key id, api key name] can be specified", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(realmName);
        out.writeOptionalString(userName);
        out.writeOptionalString(id);
        out.writeOptionalString(name);
        if (out.getVersion().onOrAfter(Version.V_7_4_0)) {
            out.writeOptionalBoolean(myApiKeysOnly);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        InvalidateApiKeyRequest that = (InvalidateApiKeyRequest) o;
        return myApiKeysOnly == that.myApiKeysOnly &&
            Objects.equals(realmName, that.realmName) &&
            Objects.equals(userName, that.userName) &&
            Objects.equals(id, that.id) &&
            Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(realmName, userName, id, name, myApiKeysOnly);
    }
}
