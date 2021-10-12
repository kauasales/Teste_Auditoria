/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.upgrades;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.AbstractDiffable;
import org.elasticsearch.cluster.Diff;
import org.elasticsearch.cluster.DiffableUtils;
import org.elasticsearch.cluster.NamedDiff;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.xcontent.ConstructingObjectParser;
import org.elasticsearch.xcontent.ParseField;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Holds the results of the most recent attempt to migrate system indices. Updated by {@link SystemIndexMigrator} as it finishes each
 * feature, or fails.
 */
public class SystemIndexMigrationResult implements Metadata.Custom {
    public static final String TYPE = "system_index_migration";
    private static final Version MIGRATION_ADDED_VERSION = Version.V_8_0_0;

    private static final ParseField RESULTS_FIELD = new ParseField("results");

    @SuppressWarnings("unchecked")
    public static final ConstructingObjectParser<SystemIndexMigrationResult, Void> PARSER = new ConstructingObjectParser<>(TYPE, a -> {
        final Map<String, FeatureMigrationStatus> statuses = ((List<Tuple<String, FeatureMigrationStatus>>) a[0]).stream()
            .collect(Collectors.toMap(Tuple::v1, Tuple::v2));
        return new SystemIndexMigrationResult(statuses);
    });

    static {
        PARSER.declareNamedObjects(
            ConstructingObjectParser.constructorArg(),
            (p, c, n) -> new Tuple<>(n, FeatureMigrationStatus.fromXContent(p)),
            v -> { throw new IllegalArgumentException("ordered " + RESULTS_FIELD.getPreferredName() + " are not supported"); },
            RESULTS_FIELD
        );
    }

    private final Map<String, FeatureMigrationStatus> featureStatuses;

    public SystemIndexMigrationResult(Map<String, FeatureMigrationStatus> featureStatuses) {
        this.featureStatuses = Objects.requireNonNullElse(featureStatuses, new HashMap<>());
    }

    public SystemIndexMigrationResult(StreamInput in) throws IOException {
        this.featureStatuses = in.readMap(StreamInput::readString, FeatureMigrationStatus::new);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMap(
            featureStatuses,
            (StreamOutput outStream, String featureName) -> outStream.writeString(featureName),
            (StreamOutput outStream, FeatureMigrationStatus featureStatus) -> featureStatus.writeTo(outStream)
        );
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.field(RESULTS_FIELD.getPreferredName(), featureStatuses);
        return builder;
    }

    public static SystemIndexMigrationResult fromXContent(XContentParser parser) {
        return PARSER.apply(parser, null);
    }

    /**
     * Gets a map of feature name to that feature's status. Only contains features which have either been migrated successfully or
     * failed to migrate.
     * @return An unmodifiable map of feature names to migration statuses.
     */
    public Map<String, FeatureMigrationStatus> getFeatureStatuses() {
        return Collections.unmodifiableMap(featureStatuses);
    }

    /**
     * Convenience method for updating the results of a migration run. Produces a new {@link SystemIndexMigrationResult} updated with the
     * given status for the given feature name.
     * @param featureName The feature name to update. If this feature name is already present, its status will be overwritten.
     * @param status The status that should be associated with the given {@code featureName}.
     * @return A new {@link SystemIndexMigrationResult} with the given status associated with the given feature name. Other entries in the
     *         map are unchanged.
     */
    public SystemIndexMigrationResult withResult(String featureName, FeatureMigrationStatus status) {
        Map<String, FeatureMigrationStatus> newMap = new HashMap<>(featureStatuses);
        newMap.put(featureName, status);
        return new SystemIndexMigrationResult(newMap);
    }

    @Override
    public EnumSet<Metadata.XContentContext> context() {
        return Metadata.ALL_CONTEXTS;
    }

    @Override
    public String getWriteableName() {
        return TYPE;
    }

    @Override
    public Version getMinimalSupportedVersion() {
        return MIGRATION_ADDED_VERSION;
    }

    @Override
    public String toString() {
        return "SystemIndexMigrationResult{" + "featureStatuses=" + featureStatuses + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if ((o instanceof SystemIndexMigrationResult) == false) return false;
        SystemIndexMigrationResult that = (SystemIndexMigrationResult) o;
        return featureStatuses.equals(that.featureStatuses);
    }

    @Override
    public int hashCode() {
        return Objects.hash(featureStatuses);
    }

    @Override
    public Diff<Metadata.Custom> diff(Metadata.Custom previousState) {
        return new ResultsDiff((SystemIndexMigrationResult) previousState, this);
    }

    public static NamedDiff<Metadata.Custom> readDiffFrom(StreamInput in) throws IOException{
        return new ResultsDiff(in);
    }

    public static class ResultsDiff implements NamedDiff<Metadata.Custom> {
        private final Diff<Map<String, FeatureMigrationStatus>> resultsDiff;

        public ResultsDiff(SystemIndexMigrationResult before, SystemIndexMigrationResult after) {
            this.resultsDiff = DiffableUtils.diff(before.featureStatuses, after.featureStatuses, DiffableUtils.getStringKeySerializer());
        }

        public ResultsDiff(StreamInput in) throws IOException {
            this.resultsDiff = DiffableUtils.readJdkMapDiff(
                in,
                DiffableUtils.getStringKeySerializer(),
                FeatureMigrationStatus::new,
                ResultsDiff::readDiffFrom
            );
        }

        @Override
        public Metadata.Custom apply(Metadata.Custom part) {
            TreeMap<String, FeatureMigrationStatus> newResults = new TreeMap<>(
                resultsDiff.apply(((SystemIndexMigrationResult) part).featureStatuses)
            );
            return new SystemIndexMigrationResult(newResults);
        }

        @Override
        public String getWriteableName() {
            return TYPE;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            resultsDiff.writeTo(out);
        }

        static Diff<FeatureMigrationStatus> readDiffFrom(StreamInput in) throws IOException {
            return AbstractDiffable.readDiffFrom(FeatureMigrationStatus::new, in);
        }
    }

}
