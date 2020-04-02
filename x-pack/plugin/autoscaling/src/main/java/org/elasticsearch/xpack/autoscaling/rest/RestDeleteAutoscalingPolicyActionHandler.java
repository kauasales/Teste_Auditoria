/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.autoscaling.rest;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.action.RestToXContentListener;
import org.elasticsearch.xpack.autoscaling.action.DeleteAutoscalingPolicyAction;

import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.DELETE;

public class RestDeleteAutoscalingPolicyActionHandler extends BaseRestHandler {

    @Override
    public List<Route> routes() {
        return List.of(new Route(DELETE, "/_autoscaling/policy/{name}"));
    }

    @Override
    public String getName() {
        return "delete_autoscaling_policy";
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest restRequest, final NodeClient client) {
        final String name = restRequest.param("name");
        final DeleteAutoscalingPolicyAction.Request request = new DeleteAutoscalingPolicyAction.Request(name);
        return channel -> client.execute(DeleteAutoscalingPolicyAction.INSTANCE, request, new RestToXContentListener<>(channel));
    }

}
