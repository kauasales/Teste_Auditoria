/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.security.rest.action.privilege;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.iterable.Iterables;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.action.RestBuilderListener;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesRequestBuilder;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesResponse;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilege;
import org.elasticsearch.xpack.core.security.client.SecurityClient;
import org.elasticsearch.xpack.security.rest.action.SecurityBaseRestHandler;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.elasticsearch.rest.RestRequest.Method.POST;

/**
 * Rest endpoint to add one or more {@link ApplicationPrivilege} objects to the security index
 */
public class RestPutPrivilegesAction extends SecurityBaseRestHandler {

    public RestPutPrivilegesAction(Settings settings, RestController controller, XPackLicenseState licenseState) {
        super(settings, licenseState);
        controller.registerHandler(POST, "/_xpack/security/privilege/", this);
    }

    @Override
    public String getName() {
        return "xpack_security_put_privileges_action";
    }

    @Override
    public RestChannelConsumer innerPrepareRequest(RestRequest request, NodeClient client) throws IOException {
        PutPrivilegesRequestBuilder requestBuilder = new SecurityClient(client)
                .preparePutPrivileges(request.requiredContent(), request.getXContentType())
                .setRefreshPolicy(request.param("refresh"));

        return execute(requestBuilder);
    }

    static RestChannelConsumer execute(PutPrivilegesRequestBuilder requestBuilder) {
        return channel -> requestBuilder.execute(new RestBuilderListener<PutPrivilegesResponse>(channel) {
            @Override
            public RestResponse buildResponse(PutPrivilegesResponse response, XContentBuilder builder) throws Exception {
                final List<ApplicationPrivilege> privileges = requestBuilder.request().getPrivileges();
                Map<String, Map<String, Map<String, Boolean>>> result = new HashMap<>();
                privileges.stream()
                        .map(ApplicationPrivilege::getApplication)
                        .distinct()
                        .forEach(a -> result.put(a, new HashMap<>()));
                privileges.forEach(privilege -> {
                    assert privilege.name().size() == 1 : "Privilege name [" + privilege.name() + "] should have a single value";
                    String name = privilege.getPrivilegeName();
                    boolean created = response.created().getOrDefault(privilege.getApplication(), Collections.emptyList()).contains(name);
                    result.get(privilege.getApplication()).put(name, Collections.singletonMap("created", created));
                });
                builder.map(result);
                return new BytesRestResponse(RestStatus.OK, builder);
            }
        });
    }

}
