/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.deprecation;

import org.elasticsearch.action.admin.cluster.node.info.PluginsAndModules;
import org.elasticsearch.bootstrap.BootstrapSettings;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.coordination.JoinHelper;
import org.elasticsearch.cluster.node.DiscoveryNodeRole;
import org.elasticsearch.cluster.routing.allocation.DataTier;
import org.elasticsearch.cluster.routing.allocation.DiskThresholdSettings;
import org.elasticsearch.cluster.routing.allocation.decider.DiskThresholdDecider;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.ssl.SslConfigurationKeys;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.gateway.GatewayService;
import org.elasticsearch.jdk.JavaVersion;
import org.elasticsearch.license.License;
import org.elasticsearch.license.XPackLicenseState;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeRoleSettings;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.FixedExecutorBuilder;
import org.elasticsearch.transport.RemoteClusterService;
import org.elasticsearch.transport.SniffConnectionStrategy;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.deprecation.DeprecationIssue;
import org.elasticsearch.xpack.core.security.SecurityField;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.authc.RealmSettings;
import org.elasticsearch.xpack.core.security.authc.esnative.NativeRealmSettings;
import org.elasticsearch.xpack.core.security.authc.file.FileRealmSettings;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.elasticsearch.cluster.routing.allocation.DiskThresholdSettings.CLUSTER_ROUTING_ALLOCATION_INCLUDE_RELOCATIONS_SETTING;
import static org.elasticsearch.xpack.cluster.routing.allocation.DataTierAllocationDecider.CLUSTER_ROUTING_EXCLUDE_SETTING;
import static org.elasticsearch.xpack.cluster.routing.allocation.DataTierAllocationDecider.CLUSTER_ROUTING_INCLUDE_SETTING;
import static org.elasticsearch.xpack.cluster.routing.allocation.DataTierAllocationDecider.CLUSTER_ROUTING_REQUIRE_SETTING;
import static org.elasticsearch.xpack.core.security.authc.RealmSettings.RESERVED_REALM_NAME_PREFIX;
import static org.elasticsearch.xpack.core.security.authc.saml.SamlRealmSettings.PRINCIPAL_ATTRIBUTE;

class NodeDeprecationChecks {

    static final String JAVA_DEPRECATION_MESSAGE = "Java 11 is required in 8.0";

    static DeprecationIssue checkPidfile(final Settings settings, final PluginsAndModules pluginsAndModules,
                                         final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkDeprecatedSetting(
            settings,
            pluginsAndModules,
            Environment.PIDFILE_SETTING,
            Environment.NODE_PIDFILE_SETTING,
            "https://ela.st/es-deprecation-7-pidfile-setting");
    }

    static DeprecationIssue checkProcessors(final Settings settings , final PluginsAndModules pluginsAndModules,
                                            final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkDeprecatedSetting(
            settings,
            pluginsAndModules,
            EsExecutors.PROCESSORS_SETTING,
            EsExecutors.NODE_PROCESSORS_SETTING,
            "https://ela.st/es-deprecation-7-processors-setting");
    }

    static DeprecationIssue checkMissingRealmOrders(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                    final ClusterState clusterState, final XPackLicenseState licenseState) {
        final Set<String> orderNotConfiguredRealms = RealmSettings.getRealmSettings(settings).entrySet()
                .stream()
                .filter(e -> false == e.getValue().hasValue(RealmSettings.ORDER_SETTING_KEY))
                .filter(e -> e.getValue().getAsBoolean(RealmSettings.ENABLED_SETTING_KEY, true))
                .map(e -> RealmSettings.realmSettingPrefix(e.getKey()) + RealmSettings.ORDER_SETTING_KEY)
                .collect(Collectors.toSet());

        if (orderNotConfiguredRealms.isEmpty()) {
            return null;
        }

        final String details = String.format(
            Locale.ROOT,
            "Specify the realm order for all realms [%s]. If no realm order is specified, the node will fail to start in 8.0. ",
            String.join("; ", orderNotConfiguredRealms));
        return new DeprecationIssue(
            DeprecationIssue.Level.CRITICAL,
            "Realm order is required",
            "https://ela.st/es-deprecation-7-realm-orders-required",
            details,
            false,
            null
        );
    }

    static DeprecationIssue checkUniqueRealmOrders(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                   final ClusterState clusterState, final XPackLicenseState licenseState) {
        final Map<String, List<String>> orderToRealmSettings =
            RealmSettings.getRealmSettings(settings).entrySet()
                .stream()
                .filter(e -> e.getValue().hasValue(RealmSettings.ORDER_SETTING_KEY))
                .collect(Collectors.groupingBy(
                    e -> e.getValue().get(RealmSettings.ORDER_SETTING_KEY),
                    Collectors.mapping(e -> RealmSettings.realmSettingPrefix(e.getKey()) + RealmSettings.ORDER_SETTING_KEY,
                        Collectors.toList())));

        Set<String> duplicateOrders = orderToRealmSettings.entrySet().stream()
            .filter(entry -> entry.getValue().size() > 1)
            .map(entry -> entry.getKey() + ": " + entry.getValue())
            .collect(Collectors.toSet());

        if (duplicateOrders.isEmpty()) {
            return null;
        }

        final String details = String.format(
            Locale.ROOT,
            "The same order is configured for multiple realms: [%s]]. Configure a unique order for each realm. If duplicate realm orders " +
                "exist, the node will fail to start in 8.0. ",
            String.join("; ", duplicateOrders));

        return new DeprecationIssue(
            DeprecationIssue.Level.CRITICAL,
            "Realm orders must be unique",
            "https://ela.st/es-deprecation-7-realm-orders-unique",
            details,
           false, null
        );
    }

    static DeprecationIssue checkImplicitlyDisabledSecurityOnBasicAndTrial(final Settings settings,
                                                                           final PluginsAndModules pluginsAndModules,
                                                                           final ClusterState clusterState,
                                                                           final XPackLicenseState licenseState) {
        if ( XPackSettings.SECURITY_ENABLED.exists(settings) == false
            && (licenseState.getOperationMode().equals(License.OperationMode.BASIC)
            || licenseState.getOperationMode().equals(License.OperationMode.TRIAL))) {
          String details = "Security will no longer be disabled by default for Trial licenses in 8.0. The [xpack.security.enabled] " +
              "setting will always default to \"true\". See https://ela.st/es-deprecation-7-security-minimal-setup to secure your cluster" +
              ". To explicitly disable security, set [xpack.security.enabled] to \"false\" (not recommended).";
            return new DeprecationIssue(
                DeprecationIssue.Level.CRITICAL,
                "Security is enabled by default for all licenses",
                "https://ela.st/es-deprecation-7-implicitly-disabled-security",
                details,
               false, null);
        }
        return null;
    }

    static DeprecationIssue checkImplicitlyDisabledBasicRealms(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                               final ClusterState clusterState, final XPackLicenseState licenseState) {
        final Map<RealmConfig.RealmIdentifier, Settings> realmSettings = RealmSettings.getRealmSettings(settings);
        if (realmSettings.isEmpty()) {
            return null;
        }

        boolean anyRealmEnabled = false;
        final Set<String> unconfiguredBasicRealms =
            new HashSet<>(org.elasticsearch.core.Set.of(FileRealmSettings.TYPE, NativeRealmSettings.TYPE));
        for (Map.Entry<RealmConfig.RealmIdentifier, Settings> realmSetting: realmSettings.entrySet()) {
            anyRealmEnabled = anyRealmEnabled || realmSetting.getValue().getAsBoolean(RealmSettings.ENABLED_SETTING_KEY, true);
            unconfiguredBasicRealms.remove(realmSetting.getKey().getType());
        }

        final String details;
        if (false == anyRealmEnabled) {
            final List<String> explicitlyDisabledBasicRealms =
                Sets.difference(org.elasticsearch.core.Set.of(FileRealmSettings.TYPE, NativeRealmSettings.TYPE),
                    unconfiguredBasicRealms).stream().sorted().collect(Collectors.toList());
            if (explicitlyDisabledBasicRealms.isEmpty()) {
                return null;
            }
            details = String.format(
                Locale.ROOT,
                "Found explicitly disabled basic %s: [%s]. But %s will be enabled because no other realms are configured or enabled. " +
                    "In next major release, explicitly disabled basic realms will remain disabled.",
                explicitlyDisabledBasicRealms.size() == 1 ? "realm" : "realms",
                Strings.collectionToDelimitedString(explicitlyDisabledBasicRealms, ","),
                explicitlyDisabledBasicRealms.size() == 1 ? "it" : "they"
                );
        } else {
            if (unconfiguredBasicRealms.isEmpty()) {
                return null;
            }
            details = String.format(
                Locale.ROOT,
                "Found implicitly disabled basic %s: [%s]. %s disabled because there are other explicitly configured realms." +
                    "In next major release, basic realms will always be enabled unless explicitly disabled.",
                unconfiguredBasicRealms.size() == 1 ? "realm" : "realms",
                Strings.collectionToDelimitedString(unconfiguredBasicRealms, ","),
                unconfiguredBasicRealms.size() == 1 ? "It is" : "They are");
        }
        return new DeprecationIssue(
            DeprecationIssue.Level.WARNING,
            "File and/or native realms are enabled by default in next major release.",
            "https://ela.st/es-deprecation-7-implicitly-disabled-basic-realms",
            details,
            false,
            null
        );

    }

    static DeprecationIssue checkReservedPrefixedRealmNames(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                            final ClusterState clusterState, final XPackLicenseState licenseState) {
        final Map<RealmConfig.RealmIdentifier, Settings> realmSettings = RealmSettings.getRealmSettings(settings);
        if (realmSettings.isEmpty()) {
            return null;
        }
        List<RealmConfig.RealmIdentifier> reservedPrefixedRealmIdentifiers = new ArrayList<>();
        for (RealmConfig.RealmIdentifier realmIdentifier: realmSettings.keySet()) {
            if (realmIdentifier.getName().startsWith(RESERVED_REALM_NAME_PREFIX)) {
                reservedPrefixedRealmIdentifiers.add(realmIdentifier);
            }
        }
        if (reservedPrefixedRealmIdentifiers.isEmpty()) {
            return null;
        } else {
            return new DeprecationIssue(
                DeprecationIssue.Level.WARNING,
                "Prefixing realm names with an underscore (_) is deprecated",
                "https://ela.st/es-deprecation-7-realm-names",
                String.format(Locale.ROOT, "Rename the following realm%s in the realm chain: %s.",
                    reservedPrefixedRealmIdentifiers.size() > 1 ? "s" : "",
                    reservedPrefixedRealmIdentifiers.stream()
                        .map(rid -> RealmSettings.PREFIX + rid.getType() + "." + rid.getName())
                        .sorted()
                        .collect(Collectors.joining(", "))),
               false, null
            );
        }
    }

    static DeprecationIssue checkThreadPoolListenerQueueSize(final Settings settings) {
        return checkThreadPoolListenerSetting("thread_pool.listener.queue_size", settings);
    }

    static DeprecationIssue checkThreadPoolListenerSize(final Settings settings) {
        return checkThreadPoolListenerSetting("thread_pool.listener.size", settings);
    }

    private static DeprecationIssue checkThreadPoolListenerSetting(final String name, final Settings settings) {
        final FixedExecutorBuilder builder = new FixedExecutorBuilder(settings, "listener", 1, -1, "thread_pool.listener", true);
        final List<Setting<?>> listenerSettings = builder.getRegisteredSettings();
        final Optional<Setting<?>> setting = listenerSettings.stream().filter(s -> s.getKey().equals(name)).findFirst();
        assert setting.isPresent();
        return checkRemovedSetting(
            settings,
            setting.get(),
            "https://ela.st/es-deprecation-7-thread-pool-listener-settings",
            "The listener pool is no longer used in 8.0.");
    }

    public static DeprecationIssue checkClusterRemoteConnectSetting(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                                    final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkDeprecatedSetting(
            settings,
            pluginsAndModules,
            RemoteClusterService.ENABLE_REMOTE_CLUSTERS,
            Setting.boolSetting(
                "node.remote_cluster_client",
                RemoteClusterService.ENABLE_REMOTE_CLUSTERS,
                Property.Deprecated,
                Property.NodeScope),
            "https://ela.st/es-deprecation-7-cluster-remote-connect-setting"
        );
    }

    public static DeprecationIssue checkNodeLocalStorageSetting(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                                final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkRemovedSetting(
            settings,
            Node.NODE_LOCAL_STORAGE_SETTING,
            "https://ela.st/es-deprecation-7-node-local-storage-setting",
            "All nodes require local storage in 8.0 and cannot share data paths."
        );
    }

    public static DeprecationIssue checkNodeBasicLicenseFeatureEnabledSetting(final Settings settings, Setting<?> setting) {
        return checkRemovedSetting(
            settings,
            setting,
            "https://ela.st/es-deprecation-7-xpack-basic-feature-settings",
            "Basic features are always enabled in 8.0."
        );
    }

    public static DeprecationIssue checkGeneralScriptSizeSetting(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                                 final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkDeprecatedSetting(
            settings,
            pluginsAndModules,
            ScriptService.SCRIPT_GENERAL_CACHE_SIZE_SETTING,
            ScriptService.SCRIPT_CACHE_SIZE_SETTING,
            "the script context.",
            "https://ela.st/es-deprecation-7-script-cache-size-setting"
        );
    }

    public static DeprecationIssue checkGeneralScriptExpireSetting(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                                   final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkDeprecatedSetting(
            settings,
            pluginsAndModules,
            ScriptService.SCRIPT_GENERAL_CACHE_EXPIRE_SETTING,
            ScriptService.SCRIPT_CACHE_EXPIRE_SETTING,
            "the script context.",
            "https://ela.st/es-deprecation-7-script-cache-expire-setting"
        );
    }

    public static DeprecationIssue checkGeneralScriptCompileSettings(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                                    final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkDeprecatedSetting(
            settings,
            pluginsAndModules,
            ScriptService.SCRIPT_GENERAL_MAX_COMPILATIONS_RATE_SETTING,
            ScriptService.SCRIPT_MAX_COMPILATIONS_RATE_SETTING,
            "the script context.",
            "https://ela.st/es-deprecation-7-script-max-compilations-rate-setting"
        );
    }

    public static DeprecationIssue checkLegacyRoleSettings(
        final Setting<Boolean> legacyRoleSetting,
        final Settings settings,
        final PluginsAndModules pluginsAndModules
    ) {
        assert legacyRoleSetting.isDeprecated() : legacyRoleSetting;
        if (legacyRoleSetting.exists(settings) == false) {
            return null;
        }
        String legacyRoleSettingKey = legacyRoleSetting.getKey();
        String role;
        if (legacyRoleSettingKey.isEmpty() == false && legacyRoleSettingKey.contains(".")
            && legacyRoleSettingKey.indexOf(".") <= legacyRoleSettingKey.length() + 2) {
            role = legacyRoleSettingKey.substring(legacyRoleSettingKey.indexOf(".") + 1);
        } else {
            role = "unknown"; //Should never get here, but putting these checks to avoid crashing the API just in case
        }
        final String message = String.format(
            Locale.ROOT,
            "Setting [%s] is deprecated",
            legacyRoleSettingKey);
        final String details = String.format(
            Locale.ROOT,
            "Remove the [%s] setting. Set [%s] and include the [%s] role.",
            legacyRoleSettingKey,
            NodeRoleSettings.NODE_ROLES_SETTING.getKey(),
            role);
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message,
            "https://ela.st/es-deprecation-7-node-roles", details, false, null);
    }

    static DeprecationIssue checkBootstrapSystemCallFilterSetting(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                                  final ClusterState clusterState, final XPackLicenseState licenseState) {
        return checkRemovedSetting(
            settings,
            BootstrapSettings.SYSTEM_CALL_FILTER_SETTING,
            "https://ela.st/es-deprecation-7-system-call-filter-setting",
            "System call filters are always required in 8.0."
        );
    }

    private static DeprecationIssue checkDeprecatedSetting(
        final Settings settings,
        final PluginsAndModules pluginsAndModules,
        final Setting<?> deprecatedSetting,
        final Setting<?> replacementSetting,
        final String url
    ) {
        return checkDeprecatedSetting(settings, pluginsAndModules, deprecatedSetting, replacementSetting, (v, s) -> v, url);
    }

    private static DeprecationIssue checkDeprecatedSetting(
        final Settings settings,
        final PluginsAndModules pluginsAndModules,
        final Setting<?> deprecatedSetting,
        final Setting<?> replacementSetting,
        final BiFunction<String, Settings, String> replacementValue,
        final String url
    ) {
        assert deprecatedSetting.isDeprecated() : deprecatedSetting;
        if (deprecatedSetting.exists(settings) == false) {
            return null;
        }
        final String deprecatedSettingKey = deprecatedSetting.getKey();
        final String replacementSettingKey = replacementSetting.getKey();
        final String value = deprecatedSetting.get(settings).toString();
        final String message = String.format(
            Locale.ROOT,
            "Setting [%s] is deprecated",
            deprecatedSettingKey);
        final String details = String.format(
            Locale.ROOT,
            "Remove the [%s] setting and set [%s] to [%s].",
            deprecatedSettingKey,
            replacementSettingKey,
            replacementValue.apply(value, settings));
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
    }

    private static DeprecationIssue checkDeprecatedSetting(
        final Settings settings,
        final PluginsAndModules pluginsAndModules,
        final Setting<?> deprecatedSetting,
        final Setting.AffixSetting<?> replacementSetting,
        final String star,
        final String url
    ) {
        return checkDeprecatedSetting(settings, pluginsAndModules, deprecatedSetting, replacementSetting, (v, s) -> v, star, url);
    }

    private static DeprecationIssue checkDeprecatedSetting(
        final Settings settings,
        final PluginsAndModules pluginsAndModules,
        final Setting<?> deprecatedSetting,
        final Setting.AffixSetting<?> replacementSetting,
        final BiFunction<String, Settings, String> replacementValue,
        final String star,
        final String url
    ) {
        assert deprecatedSetting.isDeprecated() : deprecatedSetting;
        if (deprecatedSetting.exists(settings) == false) {
            return null;
        }
        final String deprecatedSettingKey = deprecatedSetting.getKey();
        final String replacementSettingKey = replacementSetting.getKey();
        final String value = deprecatedSetting.get(settings).toString();
        final String message = String.format(
            Locale.ROOT,
            "Setting [%s] is deprecated",
            deprecatedSettingKey,
            replacementSettingKey);
        final String details = String.format(
            Locale.ROOT,
            "Remove the [%s] setting. Set [%s] to [%s], where * is %s",
            deprecatedSettingKey,
            replacementSettingKey,
            replacementValue.apply(value, settings),
            star);
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
    }

    static DeprecationIssue checkRemovedSetting(final Settings settings, final Setting<?> removedSetting, final String url,
                                                String additionalDetailMessage) {
        return checkRemovedSetting(settings, removedSetting, url, additionalDetailMessage, DeprecationIssue.Level.CRITICAL);
    }

    static DeprecationIssue checkRemovedSetting(final Settings settings,
                                                final Setting<?> removedSetting,
                                                final String url,
                                                String additionalDetailMessage,
                                                DeprecationIssue.Level deprecationLevel) {
        if (removedSetting.exists(settings) == false) {
            return null;
        }
        final String removedSettingKey = removedSetting.getKey();
        Object removedSettingValue = removedSetting.get(settings);
        String value;
        if (removedSettingValue instanceof TimeValue) {
            value = ((TimeValue) removedSettingValue).getStringRep();
        } else {
            value = removedSettingValue.toString();
        }
        final String message =
            String.format(Locale.ROOT, "Setting [%s] is deprecated", removedSettingKey);
        final String details =
            String.format(Locale.ROOT, "Remove the [%s] setting. %s", removedSettingKey, additionalDetailMessage);
        return new DeprecationIssue(deprecationLevel, message, url, details, false, null);
    }

    static DeprecationIssue javaVersionCheck(Settings nodeSettings, PluginsAndModules plugins, final ClusterState clusterState,
                                             final XPackLicenseState licenseState) {
        final JavaVersion javaVersion = JavaVersion.current();

        if (javaVersion.compareTo(JavaVersion.parse("11")) < 0) {
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL,
                JAVA_DEPRECATION_MESSAGE,
                "https://ela.st/es-deprecation-7-java-version",
                "This node is running Java version [" + javaVersion.toString() + "]. Consider switching to a distribution of " +
                    "Elasticsearch with a bundled JDK or upgrade. If you are already using a distribution with a bundled JDK, ensure the " +
                    "JAVA_HOME environment variable is not set.",
                false, null);
        }
        return null;
    }

    static DeprecationIssue checkMultipleDataPaths(Settings nodeSettings, PluginsAndModules plugins, final ClusterState clusterState,
                                                   final XPackLicenseState licenseState) {
        List<String> dataPaths = Environment.PATH_DATA_SETTING.get(nodeSettings);
        if (dataPaths.size() > 1) {
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL,
                "multiple [path.data] entries are deprecated, use a single data directory",
                "https://ela.st/es-deprecation-7-multiple-paths",
                "Multiple data paths are deprecated. Instead, use RAID or other system level features to utilize multiple disks.",
            false, null);
        }
        return null;
    }

    static DeprecationIssue checkDataPathsList(Settings nodeSettings, PluginsAndModules plugins, final ClusterState clusterState,
                                               final XPackLicenseState licenseState) {
        if (Environment.dataPathUsesList(nodeSettings)) {
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL,
                "Multiple data paths are not supported",
                "https://ela.st/es-deprecation-7-multiple-paths",
                "The [path.data] setting contains a list of paths. Specify a single path as a string. Use RAID or other system level " +
                    "features to utilize multiple disks. If multiple data paths are configured, the node will fail to start in 8.0. ",
                false, null);
        }
        return null;
    }

    static DeprecationIssue checkSharedDataPathSetting(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                       final ClusterState clusterState, final XPackLicenseState licenseState) {
        if (Environment.PATH_SHARED_DATA_SETTING.exists(settings)) {
            final String message = String.format(Locale.ROOT,
                "Setting [%s] is deprecated", Environment.PATH_SHARED_DATA_SETTING.getKey());
            final String url = "https://ela.st/es-deprecation-7-shared-path-settings";
            final String details = String.format(Locale.ROOT,
                "Remove the [%s] setting. This setting has had no effect since 6.0.", Environment.PATH_SHARED_DATA_SETTING.getKey());
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
        }
        return null;
    }

    static DeprecationIssue checkSingleDataNodeWatermarkSetting(final Settings settings, final PluginsAndModules pluginsAndModules,
                                                                final ClusterState clusterState, final XPackLicenseState licenseState) {
        if (DiskThresholdDecider.ENABLE_FOR_SINGLE_DATA_NODE.get(settings) == false
            && DiskThresholdDecider.ENABLE_FOR_SINGLE_DATA_NODE.exists(settings)) {
            String key = DiskThresholdDecider.ENABLE_FOR_SINGLE_DATA_NODE.getKey();
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL,
                String.format(Locale.ROOT, "Setting [%s=false] is deprecated", key),
                "https://ela.st/es-deprecation-7-disk-watermark-enable-for-single-node-setting",
                String.format(Locale.ROOT, "Remove the [%s] setting. Disk watermarks are always enabled for single node clusters in 8.0.",
                    key),false, null
            );
        }

        if (DiskThresholdDecider.ENABLE_FOR_SINGLE_DATA_NODE.get(settings) == false
            && clusterState.getNodes().getDataNodes().size() == 1 && clusterState.getNodes().getLocalNode().isMasterNode()) {
            String key = DiskThresholdDecider.ENABLE_FOR_SINGLE_DATA_NODE.getKey();
            String disableDiskDecider = DiskThresholdSettings.CLUSTER_ROUTING_ALLOCATION_DISK_THRESHOLD_ENABLED_SETTING.getKey();
            return new DeprecationIssue(DeprecationIssue.Level.WARNING,
                String.format(Locale.ROOT, "Disabling disk watermarks for single node clusters is deprecated and no longer the default",
                    key),
                "https://ela.st/es-deprecation-7-disk-watermark-enable-for-single-node-setting",
                String.format(Locale.ROOT, "Disk watermarks are always enabled in 8.0, which will affect the behavior of this single node" +
                        " cluster when you upgrade. You can set \"%s\" to false to disable" +
                        " disk based allocation.", disableDiskDecider),
                false,
                null
            );

        }

        return null;
    }

    static DeprecationIssue checkMonitoringExporterPassword(
        final Settings settings,
        final PluginsAndModules pluginsAndModules,
        ClusterState cs,
        XPackLicenseState licenseState
    ) {
        // Mimic the HttpExporter#AUTH_PASSWORD_SETTING setting here to avoid a dependency on monitoring module:
        // (just having the setting prefix and suffic here is sufficient to check on whether this setting is used)
        final Setting.AffixSetting<String> AUTH_PASSWORD_SETTING =
            Setting.affixKeySetting("xpack.monitoring.exporters.","auth.password", s -> Setting.simpleString(s));
        List<Setting<?>> passwords = AUTH_PASSWORD_SETTING.getAllConcreteSettings(settings)
            .sorted(Comparator.comparing(Setting::getKey)).collect(Collectors.toList());

        if (passwords.isEmpty()) {
            return null;
        }

        final String passwordSettings = passwords.stream().map(Setting::getKey).collect(Collectors.joining(","));
        final String message = String.format(
            Locale.ROOT,
            "Monitoring exporters must use secure passwords",
            passwordSettings
        );
        final String details = String.format(
            Locale.ROOT,
            "Remove the non-secure monitoring exporter password settings: [%s]. Configure secure passwords with " +
                "[xpack.monitoring.exporters.*.auth.secure_password].",
            passwordSettings
        );
        final String url = "https://ela.st/es-deprecation-7-monitoring-exporter-passwords";
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
    }

    static DeprecationIssue checkJoinTimeoutSetting(final Settings settings,
                                                    final PluginsAndModules pluginsAndModules,
                                                    final ClusterState clusterState,
                                                    final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            JoinHelper.JOIN_TIMEOUT_SETTING,
            "https://ela.st/es-deprecation-7-cluster-join-timeout-setting",
            "Cluster join attempts never time out in 8.0.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkSearchRemoteSettings(
        final Settings settings,
        final PluginsAndModules pluginsAndModules,
        ClusterState cs,
        XPackLicenseState licenseState
    ) {
        List<Setting<?>> remoteClusterSettings = new ArrayList<>();
        remoteClusterSettings.addAll(SniffConnectionStrategy.SEARCH_REMOTE_CLUSTERS_SEEDS.getAllConcreteSettings(settings)
            .sorted(Comparator.comparing(Setting::getKey)).collect(Collectors.toList()));
        remoteClusterSettings.addAll(SniffConnectionStrategy.SEARCH_REMOTE_CLUSTERS_PROXY.getAllConcreteSettings(settings)
            .sorted(Comparator.comparing(Setting::getKey)).collect(Collectors.toList()));
        remoteClusterSettings.addAll(RemoteClusterService.SEARCH_REMOTE_CLUSTER_SKIP_UNAVAILABLE.getAllConcreteSettings(settings)
            .sorted(Comparator.comparing(Setting::getKey)).collect(Collectors.toList()));
        if (SniffConnectionStrategy.SEARCH_REMOTE_CONNECTIONS_PER_CLUSTER.exists(settings)) {
            remoteClusterSettings.add(SniffConnectionStrategy.SEARCH_REMOTE_CONNECTIONS_PER_CLUSTER);
        }
        if (RemoteClusterService.SEARCH_REMOTE_INITIAL_CONNECTION_TIMEOUT_SETTING.exists(settings)) {
            remoteClusterSettings.add(RemoteClusterService.SEARCH_REMOTE_INITIAL_CONNECTION_TIMEOUT_SETTING);
        }
        if (RemoteClusterService.SEARCH_REMOTE_NODE_ATTRIBUTE.exists(settings)) {
            remoteClusterSettings.add(RemoteClusterService.SEARCH_REMOTE_NODE_ATTRIBUTE);
        }
        if (RemoteClusterService.SEARCH_ENABLE_REMOTE_CLUSTERS.exists(settings)) {
            remoteClusterSettings.add(RemoteClusterService.SEARCH_ENABLE_REMOTE_CLUSTERS);
        }
        if (remoteClusterSettings.isEmpty()) {
            return null;
        }
        final String remoteClusterSeedSettings = remoteClusterSettings.stream().map(Setting::getKey).collect(Collectors.joining(","));
        final String message = "Remotes for cross cluster search must be configured with cluster remote settings";
        final String details = String.format(
            Locale.ROOT,
            "Replace the search.remote settings [%s] with their secure [cluster.remote] equivalents",
            remoteClusterSeedSettings
        );
        final String url = "https://ela.st/es-deprecation-7-search-remote-settings";
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
    }

    static DeprecationIssue checkClusterRoutingAllocationIncludeRelocationsSetting(final Settings settings,
                                                                                   final PluginsAndModules pluginsAndModules,
                                                                                   final ClusterState clusterState,
                                                                                   final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            CLUSTER_ROUTING_ALLOCATION_INCLUDE_RELOCATIONS_SETTING,
            "https://ela.st/es-deprecation-7-cluster-routing-allocation-disk-include-relocations-setting",
            "Relocating shards are always taken into account in 8.0.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkFractionalByteValueSettings(final Settings settings,
                                                             final PluginsAndModules pluginsAndModules,
                                                             final ClusterState clusterState,
                                                             final XPackLicenseState licenseState) {
        Map<String, String> fractionalByteSettings = new HashMap<>();
        for (String key : settings.keySet()) {
            try {
                settings.getAsBytesSize(key, ByteSizeValue.ZERO);
                String stringValue = settings.get(key);
                if (stringValue.contains(".")) {
                    fractionalByteSettings.put(key, stringValue);
                }
            } catch (Exception ignoreThis) {
                // We expect anything that is not a byte setting to throw an exception, but we don't care about those
            }
        }
        if (fractionalByteSettings.isEmpty()) {
            return null;
        }
        String url = "https://ela.st/es-deprecation-7-fractional-byte-settings";
        String message = "Configuring fractional byte sizes is deprecated";
        String details = String.format(Locale.ROOT, "Set the following to whole numbers: [%s].",
            fractionalByteSettings.entrySet().stream().map(fractionalByteSetting -> fractionalByteSetting.getKey())
                .collect(Collectors.joining(", ")));
        return new DeprecationIssue(DeprecationIssue.Level.WARNING, message, url, details, false, null);
    }

    static DeprecationIssue checkFrozenCacheLeniency(final Settings settings,
                                                     final PluginsAndModules pluginsAndModules,
                                                     final ClusterState clusterState,
                                                     final XPackLicenseState licenseState) {
        final String cacheSizeSettingKey = "xpack.searchable.snapshot.shared_cache.size";
        Setting<ByteSizeValue> cacheSizeSetting =  Setting.byteSizeSetting(cacheSizeSettingKey,  ByteSizeValue.ZERO);
        if (cacheSizeSetting.exists(settings)) {
            ByteSizeValue cacheSize = cacheSizeSetting.get(settings);
            if (cacheSize.getBytes() > 0) {
                final List<DiscoveryNodeRole> roles = NodeRoleSettings.NODE_ROLES_SETTING.get(settings);
                if (DataTier.isFrozenNode(new HashSet<>(roles)) == false) {
                    String message = String.format(Locale.ROOT, "Only frozen nodes can have a [%s] greater than zero.",
                        cacheSizeSettingKey);
                    String url = "https://ela.st/es-deprecation-7-searchable-snapshot-shared-cache-setting";
                    String details = String.format(Locale.ROOT, "Set [%s] to zero on any node that doesn't have the [data_frozen] role.",
                        cacheSizeSettingKey);
                    return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
                }
            }
        }
        return null;
    }

    static DeprecationIssue checkSslServerEnabled(final Settings settings,
                                                   final PluginsAndModules pluginsAndModules,
                                                   final ClusterState clusterState,
                                                   final XPackLicenseState licenseState) {
        List<String> details = new ArrayList<>();
        for (String prefix : new String[] {"xpack.security.transport.ssl", "xpack.security.http.ssl"}) {
            final String enabledSettingKey = prefix + ".enabled";
            String enabledSettingValue = settings.get(enabledSettingKey);
            Settings sslSettings = settings.filter(setting -> setting.startsWith(prefix));
            if (enabledSettingValue == null && sslSettings.size() > 0) {
                String keys = sslSettings.keySet().stream().collect(Collectors.joining(","));
                String detail = String.format(Locale.ROOT, "The [%s] setting is not configured, but the following SSL settings are: [%s]." +
                        " To configure SSL, set [%s] or the node will fail to start in 8.0.",
                    enabledSettingKey, keys, enabledSettingKey);
                details.add(detail);
            }
        }
        if (details.isEmpty()) {
            return null;
        } else {
            String url = "https://ela.st/es-deprecation-7-explicit-ssl-required";
            String message = "Must explicitly enable or disable SSL to configure SSL settings";
            String detailsString = details.stream().collect(Collectors.joining("; "));
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, detailsString, false, null);
        }
    }

    static DeprecationIssue checkSslCertConfiguration(final Settings settings,
                                                      final PluginsAndModules pluginsAndModules,
                                                      final ClusterState clusterState,
                                                      final XPackLicenseState licenseState) {
        List<String> details = new ArrayList<>();
        for (String prefix : new String[]{"xpack.security.transport.ssl", "xpack.security.http.ssl"}) {
            final String enabledSettingKey = prefix + ".enabled";
            boolean sslEnabled = settings.getAsBoolean(enabledSettingKey, false);
            if (sslEnabled) {
                String keystorePathSettingKey = prefix + "." + SslConfigurationKeys.KEYSTORE_PATH;
                String keyPathSettingKey = prefix + "." + SslConfigurationKeys.KEY;
                String certificatePathSettingKey = prefix + "." + SslConfigurationKeys.CERTIFICATE;
                boolean keystorePathSettingExists = settings.get(keystorePathSettingKey) != null;
                boolean keyPathSettingExists = settings.get(keyPathSettingKey) != null;
                boolean certificatePathSettingExists = settings.get(certificatePathSettingKey) != null;
                if (keystorePathSettingExists == false && keyPathSettingExists == false && certificatePathSettingExists == false) {
                    String detail = String.format(Locale.ROOT, "None of [%s], [%s], or [%s] are set. If [%s] is true either use a " +
                            "keystore, or configure [%s] and [%s].", keystorePathSettingKey, keyPathSettingKey,
                        certificatePathSettingKey, enabledSettingKey, keyPathSettingKey, certificatePathSettingKey);
                    details.add(detail);
                } else if (keystorePathSettingExists && keyPathSettingExists && certificatePathSettingExists) {
                    String detail = String.format(Locale.ROOT, "All of [%s], [%s], and [%s] are set. Either use a keystore, or " +
                            "configure [%s] and [%s].", keystorePathSettingKey, keyPathSettingKey, certificatePathSettingKey,
                        keyPathSettingKey, certificatePathSettingKey);
                    details.add(detail);
                } else if (keystorePathSettingExists && (keyPathSettingExists || certificatePathSettingExists)) {
                    String detail = String.format(Locale.ROOT, "Do not configure both [%s] and [%s]. Either" +
                            " use a keystore, or configure [%s] and [%s].",
                        keystorePathSettingKey,
                        keyPathSettingExists ? keyPathSettingKey : certificatePathSettingKey,
                        keyPathSettingKey, certificatePathSettingKey);
                    details.add(detail);
                } else if ((keyPathSettingExists && certificatePathSettingExists == false) ||
                    (keyPathSettingExists == false && certificatePathSettingExists)) {
                    String detail = String.format(Locale.ROOT, "[%s] is set but [%s] is not",
                        keyPathSettingExists ? keyPathSettingKey : certificatePathSettingKey,
                        keyPathSettingExists ? certificatePathSettingKey : keyPathSettingKey);
                    details.add(detail);
                }
            }
        }
        if (details.isEmpty()) {
            return null;
        } else {
            String url = "https://ela.st/es-deprecation-7-ssl-settings";
            String message = "Must either configure a keystore or set the key path and certificate path when SSL is enabled";
            String detailsString = details.stream().collect(Collectors.joining("; "));
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, detailsString, false, null);
        }
    }

    static DeprecationIssue checkNoPermitHandshakeFromIncompatibleBuilds(final Settings settings,
                                                                         final PluginsAndModules pluginsAndModules,
                                                                         final ClusterState clusterState,
                                                                         final XPackLicenseState licenseState,
                                                                         Supplier<String> permitsHandshakesFromIncompatibleBuildsSupplier) {
        if (permitsHandshakesFromIncompatibleBuildsSupplier.get() != null) {
            final String message = String.format(
                Locale.ROOT,
                "Setting the [%s] system property is deprecated",
                TransportService.PERMIT_HANDSHAKES_FROM_INCOMPATIBLE_BUILDS_KEY
            );
            final String details = String.format(
                Locale.ROOT,
                "Remove the [%s] system property. Handshakes from incompatible builds are not allowed in 8.0.",
                TransportService.PERMIT_HANDSHAKES_FROM_INCOMPATIBLE_BUILDS_KEY
            );
            String url = "https://ela.st/es-deprecation-7-permit-handshake-from-incompatible-builds-setting";
            return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
        }
        return null;
    }

    static DeprecationIssue checkTransportClientProfilesFilterSetting(
        final Settings settings,
        final PluginsAndModules pluginsAndModules,
        ClusterState cs,
        XPackLicenseState licenseState
    ) {
        final Setting.AffixSetting<String> transportTypeProfileSetting =
            Setting.affixKeySetting("transport.profiles.","xpack.security.type", s -> Setting.simpleString(s));
        List<Setting<?>> transportProfiles = transportTypeProfileSetting.getAllConcreteSettings(settings)
            .sorted(Comparator.comparing(Setting::getKey)).collect(Collectors.toList());

        if (transportProfiles.isEmpty()) {
            return null;
        }

        final String transportProfilesSettings = transportProfiles.stream().map(Setting::getKey).collect(Collectors.joining(","));
        final String message = String.format(
            Locale.ROOT,
            "Settings [%s] for the Transport client are deprecated",
            transportProfilesSettings
        );
        final String details = "Remove all [transport.profiles] settings. The Transport client no longer exists in 8.0.";

        final String url = "https://ela.st/es-deprecation-7-transport-profiles-settings";
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
    }

    static DeprecationIssue checkDelayClusterStateRecoverySettings(final Settings settings,
                                                                   final PluginsAndModules pluginsAndModules,
                                                                   final ClusterState clusterState,
                                                                   final XPackLicenseState licenseState) {
        List<Setting<Integer>> deprecatedSettings = new ArrayList<>();
        deprecatedSettings.add(GatewayService.EXPECTED_NODES_SETTING);
        deprecatedSettings.add(GatewayService.EXPECTED_MASTER_NODES_SETTING);
        deprecatedSettings.add(GatewayService.RECOVER_AFTER_NODES_SETTING);
        deprecatedSettings.add(GatewayService.RECOVER_AFTER_MASTER_NODES_SETTING);
        List<Setting<Integer>> existingSettings =
            deprecatedSettings.stream().filter(deprecatedSetting -> deprecatedSetting.exists(settings)).collect(Collectors.toList());
        if (existingSettings.isEmpty()) {
            return null;
        }
        final String settingNames = existingSettings.stream().map(Setting::getKey).collect(Collectors.joining(","));
        final String message = String.format(
            Locale.ROOT,
            "Delaying cluster state recovery based on the number of available master nodes is not supported",
            settingNames
        );
        final String details = String.format(
            Locale.ROOT,
            "Use gateway.expected_data_nodes to wait for a certain number of data nodes. Remove the following settings or the node will " +
                "fail to start in 8.0: [%s]",
            settingNames
        );
        final String url = "https://ela.st/es-deprecation-7-deferred-cluster-state-recovery";
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
    }

    static DeprecationIssue checkFixedAutoQueueSizeThreadpool(final Settings settings,
                                                              final PluginsAndModules pluginsAndModules,
                                                              final ClusterState clusterState,
                                                              final XPackLicenseState licenseState) {
        List<Setting<Integer>> deprecatedSettings = new ArrayList<>();
        deprecatedSettings.add(Setting.intSetting("thread_pool.search.min_queue_size", 1, Setting.Property.Deprecated));
        deprecatedSettings.add(Setting.intSetting("thread_pool.search.max_queue_size", 1, Setting.Property.Deprecated));
        deprecatedSettings.add(Setting.intSetting("thread_pool.search.auto_queue_frame_size", 1, Setting.Property.Deprecated));
        deprecatedSettings.add(Setting.intSetting("thread_pool.search.target_response_time", 1, Setting.Property.Deprecated));
        deprecatedSettings.add(Setting.intSetting("thread_pool.search_throttled.min_queue_size", 1, Setting.Property.Deprecated));
        deprecatedSettings.add(Setting.intSetting("thread_pool.search_throttled.max_queue_size", 1, Setting.Property.Deprecated));
        deprecatedSettings.add(Setting.intSetting("thread_pool.search_throttled.auto_queue_frame_size", 1, Setting.Property.Deprecated));
        deprecatedSettings.add(Setting.intSetting("thread_pool.search_throttled.target_response_time", 1, Setting.Property.Deprecated));
        List<Setting<Integer>> existingSettings =
            deprecatedSettings.stream().filter(deprecatedSetting -> deprecatedSetting.exists(settings)).collect(Collectors.toList());
        if (existingSettings.isEmpty()) {
            return null;
        }
        final String settingNames = existingSettings.stream().map(Setting::getKey).collect(Collectors.joining(","));
        final String message = "The fixed_auto_queue_size threadpool type is not supported";
        final String details = String.format(
            Locale.ROOT,
            "Remove the following settings or the node will fail to start in 8.0: [%s].",
            settingNames
        );
        final String url = "https://ela.st/es-deprecation-7-fixed-auto-queue-size-settings";
        return new DeprecationIssue(DeprecationIssue.Level.CRITICAL, message, url, details, false, null);
    }

    static DeprecationIssue checkClusterRoutingRequireSetting(final Settings settings,
                                                              final PluginsAndModules pluginsAndModules,
                                                              final ClusterState clusterState,
                                                              final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            CLUSTER_ROUTING_REQUIRE_SETTING,
            "https://ela.st/es-deprecation-7-tier-filtering-settings",
            "Use [index.routing.allocation.include._tier_preference] to control allocation to data tiers.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkClusterRoutingIncludeSetting(final Settings settings,
                                                              final PluginsAndModules pluginsAndModules,
                                                              final ClusterState clusterState,
                                                              final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            CLUSTER_ROUTING_INCLUDE_SETTING,
            "https://ela.st/es-deprecation-7-tier-filtering-settings",
            "Use [index.routing.allocation.include._tier_preference] to control allocation to data tiers.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkClusterRoutingExcludeSetting(final Settings settings,
                                                              final PluginsAndModules pluginsAndModules,
                                                              final ClusterState clusterState,
                                                              final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            CLUSTER_ROUTING_EXCLUDE_SETTING,
            "https://ela.st/es-deprecation-7-tier-filtering-settings",
            "Use [index.routing.allocation.include._tier_preference] to control allocation to data tiers.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkAcceptDefaultPasswordSetting(final Settings settings,
                                                              final PluginsAndModules pluginsAndModules,
                                                              final ClusterState clusterState,
                                                              final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            Setting.boolSetting(SecurityField.setting("authc.accept_default_password"),true, Setting.Property.Deprecated),
            "https://ela.st/es-deprecation-7-accept-default-password-setting",
            "This setting has not had any effect since 6.0.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkAcceptRolesCacheMaxSizeSetting(final Settings settings,
                                                                final PluginsAndModules pluginsAndModules,
                                                                final ClusterState clusterState,
                                                                final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            Setting.intSetting(SecurityField.setting("authz.store.roles.index.cache.max_size"), 10000, Setting.Property.Deprecated),
            "https://ela.st/es-deprecation-7-roles-index-cache-settings",
            "Native role cache settings have had no effect since 5.2.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkRolesCacheTTLSizeSetting(final Settings settings,
                                                          final PluginsAndModules pluginsAndModules,
                                                          final ClusterState clusterState,
                                                          final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            Setting.timeSetting(SecurityField.setting("authz.store.roles.index.cache.ttl"), TimeValue.timeValueMinutes(20),
                Setting.Property.Deprecated),
            "https://ela.st/es-deprecation-7-roles-index-cache-settings",
            "Native role cache settings have had no effect since 5.2.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkMaxLocalStorageNodesSetting(final Settings settings,
                                                             final PluginsAndModules pluginsAndModules,
                                                             final ClusterState clusterState,
                                                             final XPackLicenseState licenseState) {
        return checkRemovedSetting(settings,
            NodeEnvironment.MAX_LOCAL_STORAGE_NODES_SETTING,
            "https://ela.st/es-deprecation-7-node-local-storage-setting",
            "All nodes require local storage in 8.0 and cannot share data paths.",
            DeprecationIssue.Level.CRITICAL
        );
    }

    static DeprecationIssue checkSamlNameIdFormatSetting(final Settings settings,
                                                         final PluginsAndModules pluginsAndModules,
                                                         final ClusterState clusterState,
                                                         final XPackLicenseState licenseState) {
        final String principalKeySuffix = ".attributes.principal";
        List<String> detailsList =
            PRINCIPAL_ATTRIBUTE.getAttribute().getAllConcreteSettings(settings).sorted(Comparator.comparing(Setting::getKey))
                .map(concreteSamlPrincipalSetting -> {
                    String concreteSamlPrincipalSettingKey = concreteSamlPrincipalSetting.getKey();
                    int principalKeySuffixIndex = concreteSamlPrincipalSettingKey.indexOf(principalKeySuffix);
                    if (principalKeySuffixIndex > 0) {
                        String realm = concreteSamlPrincipalSettingKey.substring(0, principalKeySuffixIndex);
                        String concreteNameIdFormatSettingKey = realm + ".nameid_format";
                        if (settings.get(concreteNameIdFormatSettingKey) == null) {
                            return String.format(Locale.ROOT, "Configure \"%s\" for SAML realms: \"%s\".",
                                concreteNameIdFormatSettingKey, realm);
                        }
                    }
                    return null;
                })
                .filter(detail -> detail != null).collect(Collectors.toList());
        if (detailsList.isEmpty()) {
            return null;
        } else {
            String message = "The SAML nameid_format is not set and no longer defaults to " +
                "\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"";
            String url = "https://ela.st/es-deprecation-7-saml-nameid-format";
            String details = detailsList.stream().collect(Collectors.joining(" "));
            return new DeprecationIssue(DeprecationIssue.Level.WARNING, message, url, details, false, null);
        }
    }
}
