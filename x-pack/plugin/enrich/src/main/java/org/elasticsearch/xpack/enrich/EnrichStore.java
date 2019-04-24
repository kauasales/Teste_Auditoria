/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.enrich;

import org.elasticsearch.ResourceNotFoundException;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateUpdateTask;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.xpack.core.enrich.EnrichPolicy;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Helper methods for access and storage of an enrich policy.
 */
public class EnrichStore {

    private EnrichStore() {}

    /**
     * Adds a new enrich policy or overwrites an existing policy if there is already a policy with the same name.
     * This method can only be invoked on the elected master node.
     *
     * @param name      The unique name of the policy
     * @param policy    The policy to store
     * @param handler   The handler that gets invoked if policy has been stored or a failure has occurred.
     */
    public static void putPolicy(String name, EnrichPolicy policy, ClusterService clusterService, Consumer<Exception> handler) {
        assert clusterService.localNode().isMasterNode();

        if (Strings.isNullOrEmpty(name)) {
            throw new IllegalArgumentException("name is missing or empty");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy is missing");
        }
        // TODO: add policy validation

        final Map<String, EnrichPolicy> policies = getPolicies(clusterService.state());
        policies.put(name, policy);
        updateClusterState(policies, clusterService, handler);
    }

    /**
     * Removes an enrich policy from the policies in the cluster state. This method can only be invoked on the
     * elected master node.
     *
     * @param name      The unique name of the policy
     * @param handler   The handler that gets invoked if policy has been stored or a failure has occurred.
     */
    public static void deletePolicy(String name, ClusterService clusterService, Consumer<Exception> handler) {
        assert clusterService.localNode().isMasterNode();

        if (Strings.isNullOrEmpty(name)) {
            throw new IllegalArgumentException("name is missing or empty");
        }

        final Map<String, EnrichPolicy> policies = getPolicies(clusterService.state());
        if (policies.containsKey(name) == false) {
            throw new ResourceNotFoundException("policy [{}] not found", name);
        }

        policies.remove(name);
        updateClusterState(policies, clusterService, handler);
    }

    /**
     * Gets an enrich policy for the provided name if exists or otherwise returns <code>null</code>.
     *
     * @param name  The name of the policy to fetch
     * @return enrich policy if exists or <code>null</code> otherwise
     */
    public static EnrichPolicy getPolicy(String name, ClusterState state) {
        if (Strings.isNullOrEmpty(name)) {
            throw new IllegalArgumentException("name is missing or empty");
        }

        return getPolicies(state).get(name);
    }

    private static Map<String, EnrichPolicy> getPolicies(ClusterState state) {
        final Map<String, EnrichPolicy> policies;
        final EnrichMetadata enrichMetadata = state.metaData().custom(EnrichMetadata.TYPE);
        if (enrichMetadata != null) {
            // Make a copy, because policies map inside custom metadata is read only:
            policies = new HashMap<>(enrichMetadata.getPolicies());
        } else {
            policies = new HashMap<>();
        }
        return policies;
    }

    private static void updateClusterState(Map<String, EnrichPolicy> policies, ClusterService clusterService,
                                                 Consumer<Exception> handler) {
        clusterService.submitStateUpdateTask("update-enrich-policy", new ClusterStateUpdateTask() {

            @Override
            public ClusterState execute(ClusterState currentState) throws Exception {
                MetaData metaData = MetaData.builder(currentState.metaData())
                    .putCustom(EnrichMetadata.TYPE, new EnrichMetadata(policies))
                    .build();
                return ClusterState.builder(currentState)
                    .metaData(metaData)
                    .build();
            }

            @Override
            public void clusterStateProcessed(String source, ClusterState oldState, ClusterState newState) {
                handler.accept(null);
            }

            @Override
            public void onFailure(String source, Exception e) {
                handler.accept(e);
            }
        });
    }
}
