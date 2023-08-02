/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.action;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.client.internal.node.NodeClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.license.License;
import org.elasticsearch.license.LicenseService;
import org.elasticsearch.license.LicenseUtils;
import org.elasticsearch.protocol.xpack.XPackInfoRequest;
import org.elasticsearch.protocol.xpack.XPackInfoResponse;
import org.elasticsearch.protocol.xpack.XPackInfoResponse.FeatureSetsInfo;
import org.elasticsearch.protocol.xpack.XPackInfoResponse.FeatureSetsInfo.FeatureSet;
import org.elasticsearch.protocol.xpack.XPackInfoResponse.LicenseInfo;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.XPackBuild;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TransportXPackInfoAction extends HandledTransportAction<XPackInfoRequest, XPackInfoResponse> {

    private final LicenseService licenseService;
    private final NodeClient client;
    private final List<XPackInfoFeatureAction> infoActions;

    @Inject
    public TransportXPackInfoAction(
        TransportService transportService,
        ActionFilters actionFilters,
        LicenseService licenseService,
        NodeClient client
    ) {
        super(XPackInfoAction.NAME, transportService, actionFilters, XPackInfoRequest::new);
        this.licenseService = licenseService;
        this.client = client;
        this.infoActions = infoActions();
    }

    // overrideable for tests
    protected List<XPackInfoFeatureAction> infoActions() {
        return XPackInfoFeatureAction.ALL;
    }

    @Override
    protected void doExecute(Task task, XPackInfoRequest request, ActionListener<XPackInfoResponse> listener) {

        XPackInfoResponse.BuildInfo buildInfo = null;
        if (request.getCategories().contains(XPackInfoRequest.Category.BUILD)) {
            buildInfo = new XPackInfoResponse.BuildInfo(XPackBuild.CURRENT.shortHash(), XPackBuild.CURRENT.date());
        }

        LicenseInfo licenseInfo = null;
        if (request.getCategories().contains(XPackInfoRequest.Category.LICENSE)) {
            License license = licenseService.getLicense();
            if (license != null) {
                licenseInfo = new LicenseInfo(
                    license.uid(),
                    license.type(),
                    license.operationMode().description(),
                    LicenseUtils.status(license),
                    LicenseUtils.getExpiryDate(license)
                );
            }
        }

        FeatureSetsInfo featureSetsInfo = null;
        if (request.getCategories().contains(XPackInfoRequest.Category.FEATURES)) {
            var featureSets = new HashSet<FeatureSet>();
            Set<String> avaiableActionNames = new HashSet<>(client.getActionNames());
            for (var infoAction : infoActions) {
                // local actions are executed directly, not on a separate thread, so no thread safe collection is necessary
                if (avaiableActionNames.contains(infoAction.name())) {
                    client.executeLocally(
                        infoAction,
                        request,
                        listener.delegateFailureAndWrap((l, response) -> featureSets.add(response.getInfo()))
                    );
                } else {
                    // This can happen if a plugin has been removed from the build so the transport action does not exist
                    featureSets.add(new FeatureSet(infoAction.name(), false, false));
                }
            }
            featureSetsInfo = new FeatureSetsInfo(featureSets);
        }

        listener.onResponse(new XPackInfoResponse(buildInfo, licenseInfo, featureSetsInfo));
    }
}
