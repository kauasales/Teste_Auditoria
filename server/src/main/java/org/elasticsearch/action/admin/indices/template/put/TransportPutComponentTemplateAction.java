/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.action.admin.indices.template.put;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.template.reservedstate.ReservedComposableIndexTemplateAction;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.action.support.master.AcknowledgedTransportMasterNodeAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.block.ClusterBlockException;
import org.elasticsearch.cluster.block.ClusterBlockLevel;
import org.elasticsearch.cluster.metadata.ComponentTemplate;
import org.elasticsearch.cluster.metadata.DataLifecyclePrivilegesCheck;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.MetadataIndexTemplateService;
import org.elasticsearch.cluster.metadata.Template;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class TransportPutComponentTemplateAction extends AcknowledgedTransportMasterNodeAction<PutComponentTemplateAction.Request> {

    private final MetadataIndexTemplateService indexTemplateService;
    private final IndexScopedSettings indexScopedSettings;
    private final DataLifecyclePrivilegesCheck privilegesCheck;

    public TransportPutComponentTemplateAction(
        TransportService transportService,
        ClusterService clusterService,
        ThreadPool threadPool,
        MetadataIndexTemplateService indexTemplateService,
        ActionFilters actionFilters,
        IndexNameExpressionResolver indexNameExpressionResolver,
        IndexScopedSettings indexScopedSettings
    ) {
        this(
            transportService,
            clusterService,
            threadPool,
            indexTemplateService,
            actionFilters,
            indexNameExpressionResolver,
            indexScopedSettings,
            null
        );
    }

    @Inject
    public TransportPutComponentTemplateAction(
        TransportService transportService,
        ClusterService clusterService,
        ThreadPool threadPool,
        MetadataIndexTemplateService indexTemplateService,
        ActionFilters actionFilters,
        IndexNameExpressionResolver indexNameExpressionResolver,
        IndexScopedSettings indexScopedSettings,
        DataLifecyclePrivilegesCheck privilegesCheck
    ) {
        super(
            PutComponentTemplateAction.NAME,
            transportService,
            clusterService,
            threadPool,
            actionFilters,
            PutComponentTemplateAction.Request::new,
            indexNameExpressionResolver,
            ThreadPool.Names.SAME
        );
        this.indexTemplateService = indexTemplateService;
        this.indexScopedSettings = indexScopedSettings;
        this.privilegesCheck = privilegesCheck;
    }

    @Override
    protected ClusterBlockException checkBlock(PutComponentTemplateAction.Request request, ClusterState state) {
        return state.blocks().globalBlockedException(ClusterBlockLevel.METADATA_WRITE);
    }

    public static ComponentTemplate normalizeComponentTemplate(
        ComponentTemplate componentTemplate,
        IndexScopedSettings indexScopedSettings
    ) {
        Template template = componentTemplate.template();
        // Normalize the index settings if necessary
        if (template.settings() != null) {
            Settings.Builder builder = Settings.builder().put(template.settings()).normalizePrefix(IndexMetadata.INDEX_SETTING_PREFIX);
            Settings settings = builder.build();
            indexScopedSettings.validate(settings, true);
            template = new Template(settings, template.mappings(), template.aliases(), template.lifecycle());
            componentTemplate = new ComponentTemplate(template, componentTemplate.version(), componentTemplate.metadata());
        }

        return componentTemplate;
    }

    @Override
    protected void masterOperation(
        Task task,
        final PutComponentTemplateAction.Request request,
        final ClusterState state,
        final ActionListener<AcknowledgedResponse> listener
    ) {
        ComponentTemplate componentTemplate = normalizeComponentTemplate(request.componentTemplate(), indexScopedSettings);
        if (componentTemplate.hasDataLifecycle()) {
            var composableTemplates = indexTemplateService.getTemplatesUsingComponent(state, request.name());
            var indexPatterns = composableTemplates.values()
                .stream()
                .flatMap(it -> it.indexPatterns().stream())
                .collect(Collectors.toUnmodifiableSet());
            privilegesCheck.checkCanConfigure(
                indexPatterns.toArray(new String[0]),
                ActionListener.wrap(
                    ignored -> indexTemplateService.putComponentTemplate(
                        request.cause(),
                        request.create(),
                        request.name(),
                        request.masterNodeTimeout(),
                        componentTemplate,
                        listener
                    ),
                    listener::onFailure
                )
            );
        } else {
            indexTemplateService.putComponentTemplate(
                request.cause(),
                request.create(),
                request.name(),
                request.masterNodeTimeout(),
                componentTemplate,
                listener
            );
        }
    }

    @Override
    public Optional<String> reservedStateHandlerName() {
        return Optional.of(ReservedComposableIndexTemplateAction.NAME);
    }

    @Override
    public Set<String> modifiedKeys(PutComponentTemplateAction.Request request) {
        return Set.of(ReservedComposableIndexTemplateAction.reservedComponentName(request.name()));
    }
}
