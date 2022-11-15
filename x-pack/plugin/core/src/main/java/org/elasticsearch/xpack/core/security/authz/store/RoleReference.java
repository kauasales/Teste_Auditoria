/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.hash.MessageDigests;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RoleReference is a handle to the actual role definitions (role descriptors).
 * It has different sub-types depending on how the role descriptors should be resolved.
 */
public interface RoleReference {

    /**
     * Unique ID of the instance. Instances that have equal ID means they are equivalent
     * in terms of authorization.
     * It is currently used as cache key for role caching purpose.
     * Callers can use this value to determine whether it should skip
     * resolving the role descriptors and subsequently building the role.
     */
    RoleKey id();

    /**
     * Resolve concrete role descriptors for the roleReference.
     */
    void resolve(RoleReferenceResolver resolver, ActionListener<RolesRetrievalResult> listener);

    /**
     * Referencing a collection of role descriptors by their names
     */
    final class NamedRoleReference implements RoleReference {
        private final String[] roleNames;

        public NamedRoleReference(String[] roleNames) {
            this.roleNames = roleNames;
        }

        public String[] getRoleNames() {
            return roleNames;
        }

        @Override
        public RoleKey id() {
            if (roleNames.length == 0) {
                return RoleKey.ROLE_KEY_EMPTY;
            } else {
                final Set<String> distinctRoles = new HashSet<>(List.of(roleNames));
                if (distinctRoles.size() == 1 && distinctRoles.contains(ReservedRolesStore.SUPERUSER_ROLE_DESCRIPTOR.getName())) {
                    return RoleKey.ROLE_KEY_SUPERUSER;
                } else {
                    return new RoleKey(Set.copyOf(distinctRoles), RoleKey.ROLES_STORE_SOURCE);
                }
            }
        }

        @Override
        public void resolve(RoleReferenceResolver resolver, ActionListener<RolesRetrievalResult> listener) {
            resolver.resolveNamedRoleReference(this, listener);
        }
    }

    /**
     * Referencing API Key role descriptors. Can be either the assigned (key) role descriptors or the limited-by (owner's) role descriptors
     */
    final class ApiKeyRoleReference implements RoleReference {

        private final String apiKeyId;
        private final BytesReference roleDescriptorsBytes;
        private final ApiKeyRoleType roleType;
        private RoleKey id = null;

        public ApiKeyRoleReference(String apiKeyId, BytesReference roleDescriptorsBytes, ApiKeyRoleType roleType) {
            this.apiKeyId = apiKeyId;
            this.roleDescriptorsBytes = roleDescriptorsBytes;
            this.roleType = roleType;
        }

        @Override
        public RoleKey id() {
            // Hashing can be expensive. memorize the result in case the method is called multiple times.
            if (id == null) {
                final String roleDescriptorsHash = MessageDigests.toHexString(
                    MessageDigests.digest(roleDescriptorsBytes, MessageDigests.sha256())
                );
                id = new RoleKey(Set.of("apikey:" + roleDescriptorsHash), "apikey_" + roleType);
            }
            return id;
        }

        @Override
        public void resolve(RoleReferenceResolver resolver, ActionListener<RolesRetrievalResult> listener) {
            resolver.resolveApiKeyRoleReference(this, listener);
        }

        public String getApiKeyId() {
            return apiKeyId;
        }

        public BytesReference getRoleDescriptorsBytes() {
            return roleDescriptorsBytes;
        }

        public ApiKeyRoleType getRoleType() {
            return roleType;
        }
    }

    /**
     * Same as {@link ApiKeyRoleReference} but for BWC purpose (prior to v7.9.0)
     */
    final class BwcApiKeyRoleReference implements RoleReference {
        private final String apiKeyId;
        private final Map<String, Object> roleDescriptorsMap;
        private final ApiKeyRoleType roleType;

        public BwcApiKeyRoleReference(String apiKeyId, Map<String, Object> roleDescriptorsMap, ApiKeyRoleType roleType) {
            this.apiKeyId = apiKeyId;
            this.roleDescriptorsMap = roleDescriptorsMap;
            this.roleType = roleType;
        }

        @Override
        public RoleKey id() {
            // Since api key id is unique, it is sufficient and more correct to use it as the names
            return new RoleKey(Set.of(apiKeyId), "bwc_api_key_" + roleType);
        }

        @Override
        public void resolve(RoleReferenceResolver resolver, ActionListener<RolesRetrievalResult> listener) {
            resolver.resolveBwcApiKeyRoleReference(this, listener);
        }

        public String getApiKeyId() {
            return apiKeyId;
        }

        public Map<String, Object> getRoleDescriptorsMap() {
            return roleDescriptorsMap;
        }

        public ApiKeyRoleType getRoleType() {
            return roleType;
        }
    }

    /**
     * Referencing role descriptors by the service account principal
     */
    final class ServiceAccountRoleReference implements RoleReference {
        private final String principal;

        public ServiceAccountRoleReference(String principal) {
            this.principal = principal;
        }

        public String getPrincipal() {
            return principal;
        }

        @Override
        public RoleKey id() {
            return new RoleKey(Set.of(principal), "service_account");
        }

        @Override
        public void resolve(RoleReferenceResolver resolver, ActionListener<RolesRetrievalResult> listener) {
            resolver.resolveServiceAccountRoleReference(this, listener);
        }
    }

    /**
     * Referencing Cross Cluster role descriptors. It is a list of 1-2 QC role descriptors and 2 FC role descriptors (3-4 total).
     */
    final class CrossClusterRoleReference implements RoleReference {

        private final String qcId;
        private final String fcId;
        private final BytesReference roleDescriptorsBytes;
        private RoleKey cacheKey = null;

        public CrossClusterRoleReference(final String qcId, final String fcId, final BytesReference roleDescriptorsBytes) {
            this.qcId = qcId;
            this.fcId = fcId;
            this.roleDescriptorsBytes = roleDescriptorsBytes;
        }

        @Override
        public RoleKey id() {
            // Hashing can be expensive. memorize the result in case the method is called multiple times.
            if (this.cacheKey == null) {
                final String roleDescriptorsHash = MessageDigests.toHexString(
                    MessageDigests.digest(this.roleDescriptorsBytes, MessageDigests.sha256())
                );
                this.cacheKey = new RoleKey(Set.of("crossCluster:" + roleDescriptorsHash), "crossCluster");
            }
            return this.cacheKey;
        }

        @Override
        public void resolve(RoleReferenceResolver resolver, ActionListener<RolesRetrievalResult> listener) {
            resolver.resolveCrossClusterRoleReference(this, listener);
        }

        public String getQcId() {
            return this.qcId;
        }

        public String getFcId() {
            return this.fcId;
        }

        public BytesReference getRoleDescriptorsBytes() {
            return this.roleDescriptorsBytes;
        }
    }

    /**
     * The type of one set of API key roles.
     */
    enum ApiKeyRoleType {
        /**
         * Roles directly specified by the creator user on API key creation
         */
        ASSIGNED,
        /**
         * Roles captured for the owner user as the upper bound of the assigned roles
         */
        LIMITED_BY;
    }
}
