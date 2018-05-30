/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.core.ml.job.config;

import org.elasticsearch.Version;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.LoggingDeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.xpack.core.ml.MlParserType;
import org.elasticsearch.xpack.core.ml.job.messages.Messages;
import org.elasticsearch.xpack.core.ml.utils.ExceptionsHelper;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class DetectionRule implements ToXContentObject, Writeable {

    public static final Version VERSION_INTRODUCED = Version.V_6_4_0;

    public static final ParseField DETECTION_RULE_FIELD = new ParseField("detection_rule");
    public static final ParseField ACTIONS_FIELD = new ParseField("actions");
    public static final ParseField SCOPE_FIELD = new ParseField("scope");
    public static final ParseField CONDITIONS_FIELD = new ParseField("conditions");

    // These parsers follow the pattern that metadata is parsed leniently (to allow for enhancements), whilst config is parsed strictly
    public static final ObjectParser<Builder, Void> METADATA_PARSER =
            new ObjectParser<>(DETECTION_RULE_FIELD.getPreferredName(), true, Builder::new);
    public static final ObjectParser<Builder, Void> CONFIG_PARSER =
            new ObjectParser<>(DETECTION_RULE_FIELD.getPreferredName(), false, Builder::new);
    public static final Map<MlParserType, ObjectParser<Builder, Void>> PARSERS = new EnumMap<>(MlParserType.class);

    static {
        PARSERS.put(MlParserType.METADATA, METADATA_PARSER);
        PARSERS.put(MlParserType.CONFIG, CONFIG_PARSER);
        for (MlParserType parserType : MlParserType.values()) {
            ObjectParser<Builder, Void> parser = PARSERS.get(parserType);
            assert parser != null;
            parser.declareStringArray(Builder::setActions, ACTIONS_FIELD);
            parser.declareObject(Builder::setScope, (p, c) -> {
                Map<String, Object> unparsedScope = p.map();
                if (unparsedScope.isEmpty()) {
                    return new RuleScope();
                }
                ConstructingObjectParser<FilterRef, Void> filterRefParser = FilterRef.PARSERS.get(parserType);
                Map<String, FilterRef> scope = new HashMap<>();
                for (Map.Entry<String, Object> entry : unparsedScope.entrySet()) {
                    try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
                        builder.map((Map<String, ?>) entry.getValue());
                        try (XContentParser scopeParser = XContentFactory.xContent(builder.contentType()).createParser(
                                NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, Strings.toString(builder))) {
                            scope.put(entry.getKey(), filterRefParser.parse(scopeParser, null));
                        }
                    }
                }
                return new RuleScope(scope);
            }, SCOPE_FIELD);
            parser.declareObjectArray(Builder::setConditions, (p, c) ->
                    RuleCondition.PARSERS.get(parserType).apply(p, c), CONDITIONS_FIELD);
        }
    }

    private final EnumSet<RuleAction> actions;
    private final RuleScope scope;
    private final List<RuleCondition> conditions;

    private DetectionRule(EnumSet<RuleAction> actions, RuleScope scope, List<RuleCondition> conditions) {
        this.actions = Objects.requireNonNull(actions);
        this.scope = Objects.requireNonNull(scope);
        this.conditions = Collections.unmodifiableList(conditions);
    }

    public DetectionRule(StreamInput in) throws IOException {
        actions = in.readEnumSet(RuleAction.class);
        scope = new RuleScope(in);
        conditions = in.readList(RuleCondition::new);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        if (out.getVersion().onOrAfter(Version.V_6_4_0)) {
            out.writeEnumSet(actions);
            scope.writeTo(out);
            out.writeList(conditions);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(ACTIONS_FIELD.getPreferredName(), actions);
        if (scope.isEmpty() == false) {
            builder.field(SCOPE_FIELD.getPreferredName(), scope);
        }
        if (conditions.isEmpty() == false) {
            builder.field(CONDITIONS_FIELD.getPreferredName(), conditions);
        }
        builder.endObject();
        return builder;
    }

    public EnumSet<RuleAction> getActions() {
        return actions;
    }

    public RuleScope getScope() {
        return scope;
    }

    public List<RuleCondition> getConditions() {
        return conditions;
    }

    public Set<String> extractReferencedFilters() {
        return scope.getReferencedFilters();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof DetectionRule == false) {
            return false;
        }

        DetectionRule other = (DetectionRule) obj;
        return Objects.equals(actions, other.actions)
                && Objects.equals(scope, other.scope)
                && Objects.equals(conditions, other.conditions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(actions, scope, conditions);
    }

    public static class Builder {
        private EnumSet<RuleAction> actions = EnumSet.of(RuleAction.SKIP_RESULT);
        private RuleScope scope = new RuleScope();
        private List<RuleCondition> conditions = Collections.emptyList();

        public Builder(RuleScope.Builder scope) {
            this.scope = scope.build();
        }

        public Builder(List<RuleCondition> conditions) {
            this.conditions = ExceptionsHelper.requireNonNull(conditions, CONDITIONS_FIELD.getPreferredName());
        }

        Builder() {
        }

        public Builder setActions(List<String> actions) {
            this.actions.clear();
            actions.stream().map(RuleAction::fromString).forEach(this.actions::add);
            return this;
        }

        public Builder setActions(EnumSet<RuleAction> actions) {
            this.actions = Objects.requireNonNull(actions, ACTIONS_FIELD.getPreferredName());
            return this;
        }

        public Builder setActions(RuleAction... actions) {
            this.actions.clear();
            Arrays.stream(actions).forEach(this.actions::add);
            return this;
        }

        public Builder setScope(RuleScope scope) {
            this.scope = Objects.requireNonNull(scope);
            return this;
        }

        public Builder setConditions(List<RuleCondition> conditions) {
            this.conditions = ExceptionsHelper.requireNonNull(conditions, CONDITIONS_FIELD.getPreferredName());
            return this;
        }

        public DetectionRule build() {
            if (scope.isEmpty() && conditions.isEmpty()) {
                String msg = Messages.getMessage(Messages.JOB_CONFIG_DETECTION_RULE_REQUIRES_SCOPE_OR_CONDITION);
                throw ExceptionsHelper.badRequestException(msg);
            }
            return new DetectionRule(actions, scope, conditions);
        }
    }
}
