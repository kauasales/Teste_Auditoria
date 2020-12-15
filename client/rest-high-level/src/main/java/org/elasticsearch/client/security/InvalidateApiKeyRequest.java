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

package org.elasticsearch.client.security;

import org.elasticsearch.client.Validatable;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * Request for invalidating API key(s) so that it can no longer be used
 */
public final class InvalidateApiKeyRequest implements Validatable, ToXContentObject {

    private final String realmName;
    private final String userName;
    private final String[] ids;
    private final String name;
    private final boolean ownedByAuthenticatedUser;

    // pkg scope for testing
    @Deprecated
    InvalidateApiKeyRequest(@Nullable String realmName, @Nullable String userName, @Nullable String apiKeyId,
                            @Nullable String apiKeyName, boolean ownedByAuthenticatedUser) {
        this(realmName, userName, apiKeyName, ownedByAuthenticatedUser, Strings.hasText(apiKeyId) ? new String[]{apiKeyId} : null);
    }

    InvalidateApiKeyRequest(@Nullable String realmName, @Nullable String userName,
                            @Nullable String apiKeyName, boolean ownedByAuthenticatedUser, @Nullable String[] apiKeyIds) {
        validateApiKeyIds(apiKeyIds);
        if (Strings.hasText(realmName) == false && Strings.hasText(userName) == false && apiKeyIds == null
            && Strings.hasText(apiKeyName) == false && ownedByAuthenticatedUser == false) {
            throwValidationError("One of [api key id, api key name, username, realm name] must be specified if [owner] flag is false");
        }
        if (apiKeyIds != null || Strings.hasText(apiKeyName)) {
            if (Strings.hasText(realmName) || Strings.hasText(userName)) {
                throwValidationError(
                    "username or realm name must not be specified when the api key id or api key name is specified");
            }
        }
        if (ownedByAuthenticatedUser) {
            if (Strings.hasText(realmName) || Strings.hasText(userName)) {
                throwValidationError("neither username nor realm-name may be specified when invalidating owned API keys");
            }
        }
        if (apiKeyIds != null && Strings.hasText(apiKeyName)) {
            throwValidationError("only one of [api key id, api key name] can be specified");
        }
        this.realmName = realmName;
        this.userName = userName;
        this.ids = apiKeyIds;
        this.name = apiKeyName;
        this.ownedByAuthenticatedUser = ownedByAuthenticatedUser;
    }

    private void validateApiKeyIds(@Nullable String[] apiKeyIds) {
        if (apiKeyIds != null) {
            if (apiKeyIds.length == 0) {
                throwValidationError("Argument [apiKeyIds] cannot be an empty array");
            } else {
                final int[] idxOfBlankIds = IntStream.range(0, apiKeyIds.length)
                    .filter(i -> Strings.hasText(apiKeyIds[i]) == false).toArray();
                if (idxOfBlankIds.length > 0) {
                    throwValidationError("Argument [apiKeyIds] must not contain blank id, but got blank "
                        + (idxOfBlankIds.length == 1 ? "id" : "ids") + " at index "
                        + (idxOfBlankIds.length == 1 ? "position" : "positions") + ": "
                        + Arrays.toString(idxOfBlankIds));
                }
            }
        }
    }

    private void throwValidationError(String message) {
        throw new IllegalArgumentException(message);
    }

    public String getRealmName() {
        return realmName;
    }

    public String getUserName() {
        return userName;
    }

    @Deprecated
    public String getId() {
        if (ids == null) {
            return null;
        } else if (ids.length == 1) {
            return ids[0];
        } else {
            throw new IllegalArgumentException("Cannot get a single api key id when multiple ids have been set " + Arrays.toString(ids));
        }
    }

    public String[] getIds() {
        return ids;
    }

    public String getName() {
        return name;
    }

    public boolean ownedByAuthenticatedUser() {
        return ownedByAuthenticatedUser;
    }

    /**
     * Creates invalidate API key request for given realm name
     * @param realmName realm name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingRealmName(String realmName) {
        return new InvalidateApiKeyRequest(realmName, null, null, false, null);
    }

    /**
     * Creates invalidate API key request for given user name
     * @param userName user name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingUserName(String userName) {
        return new InvalidateApiKeyRequest(null, userName,  null, false, null);
    }

    /**
     * Creates invalidate API key request for given realm and user name
     * @param realmName realm name
     * @param userName user name
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingRealmAndUserName(String realmName, String userName) {
        return new InvalidateApiKeyRequest(realmName, userName, null, false, null);
    }

    /**
     * Creates invalidate API key request for given api key id
     * @param apiKeyId api key id
     * @param ownedByAuthenticatedUser set {@code true} if the request is only for the API keys owned by current authenticated user else
     * {@code false}
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingApiKeyId(String apiKeyId, boolean ownedByAuthenticatedUser) {
        return new InvalidateApiKeyRequest(null, null, null, ownedByAuthenticatedUser,
            Strings.hasText(apiKeyId) ? new String[] { apiKeyId } : null);
    }

    /**
     * Creates invalidate API key request for given api key ids
     * @param apiKeyIds api key ids
     * @param ownedByAuthenticatedUser set {@code true} if the request is only for the API keys owned by current authenticated user else
     * {@code false}
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingApiKeyIds(String[] apiKeyIds, boolean ownedByAuthenticatedUser) {
        return new InvalidateApiKeyRequest(null, null, null, ownedByAuthenticatedUser, apiKeyIds);
    }

    /**
     * Creates invalidate API key request for given api key name
     * @param apiKeyName api key name
     * @param ownedByAuthenticatedUser set {@code true} if the request is only for the API keys owned by current authenticated user else
     * {@code false}
     * @return {@link InvalidateApiKeyRequest}
     */
    public static InvalidateApiKeyRequest usingApiKeyName(String apiKeyName, boolean ownedByAuthenticatedUser) {
        return new InvalidateApiKeyRequest(null, null, apiKeyName, ownedByAuthenticatedUser, null);
    }

    /**
     * Creates invalidate api key request to invalidate api keys owned by the current authenticated user.
     */
    public static InvalidateApiKeyRequest forOwnedApiKeys() {
        return new InvalidateApiKeyRequest(null, null, null, true, null);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (realmName != null) {
            builder.field("realm_name", realmName);
        }
        if (userName != null) {
            builder.field("username", userName);
        }
        if (ids != null) {
            builder.array("id", ids);
        }
        if (name != null) {
            builder.field("name", name);
        }
        builder.field("owner", ownedByAuthenticatedUser);
        return builder.endObject();
    }
}
