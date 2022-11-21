/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz;

import org.elasticsearch.action.LatchedActionListener;
import org.elasticsearch.action.support.ActionTestUtils;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.test.SecurityIntegTestCase;
import org.elasticsearch.transport.TcpTransport;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.user.AuthenticateAction;
import org.elasticsearch.xpack.core.security.action.user.AuthenticateRequest;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationTestHelper;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptorsIntersection;
import org.elasticsearch.xpack.core.security.support.NativeRealmValidationUtil;
import org.elasticsearch.xpack.core.security.user.SystemUser;
import org.elasticsearch.xpack.core.security.user.User;
import org.elasticsearch.xpack.security.audit.AuditUtil;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

public class AuthorizationServiceIntegTests extends SecurityIntegTestCase {

    @Override
    protected boolean addMockHttpTransport() {
        return false; // need real http
    }

    public void testRetrieveRemoteAccessRoleDescriptorsIntersectionForNonInternalUser() throws IOException, InterruptedException {
        assumeTrue("untrusted remote cluster feature flag must be enabled", TcpTransport.isUntrustedRemoteClusterEnabled());

        final String concreteClusterAlias = randomAlphaOfLength(10);
        final String roleName = randomAlphaOfLength(5);
        getSecurityClient().putRole(
            new RoleDescriptor(
                roleName,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                new RoleDescriptor.RemoteIndicesPrivileges[] {
                    new RoleDescriptor.RemoteIndicesPrivileges(
                        RoleDescriptor.IndicesPrivileges.builder()
                            .indices(shuffledList(List.of("index1", "index2")))
                            .privileges(shuffledList(List.of("read", "write")))
                            .build(),
                        randomNonEmptySubsetOf(List.of(concreteClusterAlias, "*")).toArray(new String[0])
                    ) }
            )
        );
        final String nodeName = internalCluster().getRandomNodeName();
        final ThreadContext threadContext = internalCluster().getInstance(SecurityContext.class, nodeName).getThreadContext();
        final AuthorizationService authzService = internalCluster().getInstance(AuthorizationService.class, nodeName);
        final Authentication authentication = Authentication.newRealmAuthentication(
            new User(randomAlphaOfLengthBetween(5, 16), roleName),
            new Authentication.RealmRef(
                randomBoolean() ? "realm" : randomAlphaOfLengthBetween(1, 16),
                randomAlphaOfLengthBetween(5, 16),
                nodeName
            )
        );
        final RoleDescriptorsIntersection actual = authorizeThenRetrieveRemoteAccessDescriptors(
            threadContext,
            authzService,
            authentication,
            concreteClusterAlias
        );
        final String generatedRoleName = actual.roleDescriptorsList().iterator().next().iterator().next().getName();
        assertNull(NativeRealmValidationUtil.validateRoleName(generatedRoleName, false));
        assertThat(generatedRoleName, not(equalTo(roleName)));
        assertThat(
            actual,
            equalTo(
                new RoleDescriptorsIntersection(
                    List.of(
                        Set.of(
                            new RoleDescriptor(
                                generatedRoleName,
                                null,
                                new RoleDescriptor.IndicesPrivileges[] {
                                    RoleDescriptor.IndicesPrivileges.builder()
                                        .indices("index1", "index2")
                                        .privileges("read", "write")
                                        .build() },
                                null,
                                null,
                                null,
                                null,
                                null
                            )
                        )
                    )
                )
            )
        );
    }

    public void testRetrieveRemoteAccessRoleDescriptorsIntersectionForInternalUser() throws InterruptedException {
        assumeTrue("untrusted remote cluster feature flag must be enabled", TcpTransport.isUntrustedRemoteClusterEnabled());

        final String nodeName = internalCluster().getRandomNodeName();
        final ThreadContext threadContext = internalCluster().getInstance(SecurityContext.class, nodeName).getThreadContext();
        final AuthorizationService authzService = internalCluster().getInstance(AuthorizationService.class, nodeName);
        final Authentication authentication = AuthenticationTestHelper.builder()
            .internal(randomValueOtherThan(SystemUser.INSTANCE, AuthenticationTestHelper::randomInternalUser))
            .build();
        final String concreteClusterAlias = randomAlphaOfLength(10);

        // For internal users, we support the situation where there is no authorization information populated in thread context
        // We test both scenarios, one where we don't authorize and don't have authorization info in thread context, and one where we do
        if (randomBoolean()) {
            final CountDownLatch latch = new CountDownLatch(1);
            final AtomicReference<RoleDescriptorsIntersection> actual = new AtomicReference<>();
            authzService.retrieveRemoteAccessRoleDescriptorsIntersection(
                concreteClusterAlias,
                authentication.getEffectiveSubject(),
                new LatchedActionListener<>(ActionTestUtils.assertNoFailureListener(actual::set), latch)
            );
            latch.await();
            assertThat(actual.get(), equalTo(RoleDescriptorsIntersection.EMPTY));
        } else {
            assertThat(
                authorizeThenRetrieveRemoteAccessDescriptors(threadContext, authzService, authentication, concreteClusterAlias),
                equalTo(RoleDescriptorsIntersection.EMPTY)
            );
        }
    }

    private RoleDescriptorsIntersection authorizeThenRetrieveRemoteAccessDescriptors(
        final ThreadContext threadContext,
        final AuthorizationService authzService,
        final Authentication authentication,
        final String concreteClusterAlias
    ) throws InterruptedException {
        try (var ignored = threadContext.stashContext()) {
            final AtomicReference<RoleDescriptorsIntersection> actual = new AtomicReference<>();
            final CountDownLatch latch = new CountDownLatch(1);
            // A request ID is set during authentication and is required for authorization; since we are not authenticating, set it
            // explicitly
            AuditUtil.generateRequestId(threadContext);
            // Authorize to populate thread context with authz info
            // Note that if the outer listener throws, we will not count down on the latch, however, we also won't get to the await call
            // since the exception will be thrown before -- so no deadlock
            authzService.authorize(
                authentication,
                AuthenticateAction.INSTANCE.name(),
                AuthenticateRequest.INSTANCE,
                ActionTestUtils.assertNoFailureListener(nothing -> {
                    authzService.retrieveRemoteAccessRoleDescriptorsIntersection(
                        concreteClusterAlias,
                        authentication.getEffectiveSubject(),
                        new LatchedActionListener<>(ActionTestUtils.assertNoFailureListener(actual::set), latch)
                    );
                })
            );
            latch.await();
            return actual.get();
        }
    }
}
