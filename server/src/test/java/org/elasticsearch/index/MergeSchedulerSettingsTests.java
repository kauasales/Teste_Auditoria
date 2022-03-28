/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.index;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.logging.Level;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.logging.api.core.Appender;
import org.elasticsearch.logging.api.core.AppenderUtils;
import org.elasticsearch.logging.api.core.Filter;
import org.elasticsearch.logging.api.core.Layout;
import org.elasticsearch.logging.api.core.LogEvent;
import org.elasticsearch.logging.internal.LogLevelUtil;
import org.elasticsearch.test.ESTestCase;

import static org.elasticsearch.common.util.concurrent.EsExecutors.NODE_PROCESSORS_SETTING;
import static org.elasticsearch.index.IndexSettingsTests.newIndexMeta;
import static org.elasticsearch.index.MergeSchedulerConfig.MAX_MERGE_COUNT_SETTING;
import static org.elasticsearch.index.MergeSchedulerConfig.MAX_THREAD_COUNT_SETTING;
import static org.hamcrest.core.StringContains.containsString;

public class MergeSchedulerSettingsTests extends ESTestCase {
    private static class MockAppender implements Appender {
        public boolean sawUpdateMaxThreadCount;
        public boolean sawUpdateAutoThrottle;

        MockAppender(final String name) throws IllegalAccessException {
            // super(name, RegexFilter.createFilter(".*(\n.*)*", new String[0], false, null, null), null);
        }

        @Override
        public Filter filter() {
            return null;
        }

        @Override
        public Layout layout() {
            return null;
        }

        @Override
        public String name() {
            return null;
        }

        // @Override
        public boolean ignoreExceptions() {
            return false;
        }

        @Override
        public void append(LogEvent event) {
            String message = event.getMessage().getFormattedMessage();
            if (event.getLevel() == Level.TRACE && event.getLoggerName().endsWith("lucene.iw")) {
            }
            if (event.getLevel() == Level.INFO
                && message.contains("updating [index.merge.scheduler.max_thread_count] from [10000] to [1]")) {
                sawUpdateMaxThreadCount = true;
            }
            if (event.getLevel() == Level.INFO
                && message.contains("updating [index.merge.scheduler.auto_throttle] from [true] to [false]")) {
                sawUpdateAutoThrottle = true;
            }
        }
    }

    public void testUpdateAutoThrottleSettings() throws Exception {
        MockAppender mockAppender = new MockAppender("testUpdateAutoThrottleSettings");
        // mockAppender.start();
        final Logger settingsLogger = LogManager.getLogger("org.elasticsearch.common.settings.IndexScopedSettings");
        AppenderUtils.addAppender(settingsLogger, mockAppender);
        LogLevelUtil.setLevel(settingsLogger, Level.TRACE);
        try {
            Settings.Builder builder = Settings.builder()
                .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, "1")
                .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, "0")
                .put(MergePolicyConfig.INDEX_MERGE_POLICY_MAX_MERGE_AT_ONCE_SETTING.getKey(), "2")
                .put(MergePolicyConfig.INDEX_MERGE_POLICY_SEGMENTS_PER_TIER_SETTING.getKey(), "2")
                .put(MergeSchedulerConfig.MAX_THREAD_COUNT_SETTING.getKey(), "1")
                .put(MergeSchedulerConfig.MAX_MERGE_COUNT_SETTING.getKey(), "2")
                .put(MergeSchedulerConfig.AUTO_THROTTLE_SETTING.getKey(), "true");
            IndexSettings settings = new IndexSettings(newIndexMeta("index", builder.build()), Settings.EMPTY);
            assertEquals(settings.getMergeSchedulerConfig().isAutoThrottle(), true);
            builder.put(MergeSchedulerConfig.AUTO_THROTTLE_SETTING.getKey(), "false");
            settings.updateIndexMetadata(newIndexMeta("index", builder.build()));
            // Make sure we log the change:
            assertTrue(mockAppender.sawUpdateAutoThrottle);
            assertEquals(settings.getMergeSchedulerConfig().isAutoThrottle(), false);
        } finally {
            AppenderUtils.removeAppender(settingsLogger, mockAppender);
            // mockAppender.stop();
            LogLevelUtil.setLevel(settingsLogger, (Level) null);
        }
    }

    // #6882: make sure we can change index.merge.scheduler.max_thread_count live
    public void testUpdateMergeMaxThreadCount() throws Exception {
        MockAppender mockAppender = new MockAppender("testUpdateAutoThrottleSettings");
        // mockAppender.start();
        final Logger settingsLogger = LogManager.getLogger("org.elasticsearch.common.settings.IndexScopedSettings");
        AppenderUtils.addAppender(settingsLogger, mockAppender);
        LogLevelUtil.setLevel(settingsLogger, Level.TRACE);
        try {
            Settings.Builder builder = Settings.builder()
                .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, "1")
                .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, "0")
                .put(MergePolicyConfig.INDEX_MERGE_POLICY_MAX_MERGE_AT_ONCE_SETTING.getKey(), "2")
                .put(MergePolicyConfig.INDEX_MERGE_POLICY_SEGMENTS_PER_TIER_SETTING.getKey(), "2")
                .put(MergeSchedulerConfig.MAX_THREAD_COUNT_SETTING.getKey(), "10000")
                .put(MergeSchedulerConfig.MAX_MERGE_COUNT_SETTING.getKey(), "10000");
            IndexSettings settings = new IndexSettings(newIndexMeta("index", builder.build()), Settings.EMPTY);
            assertEquals(settings.getMergeSchedulerConfig().getMaxMergeCount(), 10000);
            assertEquals(settings.getMergeSchedulerConfig().getMaxThreadCount(), 10000);
            settings.updateIndexMetadata(newIndexMeta("index", builder.build()));
            assertFalse(mockAppender.sawUpdateMaxThreadCount);
            builder.put(MergeSchedulerConfig.MAX_THREAD_COUNT_SETTING.getKey(), "1");
            settings.updateIndexMetadata(newIndexMeta("index", builder.build()));
            // Make sure we log the change:
            assertTrue(mockAppender.sawUpdateMaxThreadCount);
        } finally {
            AppenderUtils.removeAppender(settingsLogger, mockAppender);
            // mockAppender.stop();
            LogLevelUtil.setLevel(settingsLogger, (Level) null);
        }
    }

    private static IndexMetadata createMetadata(int maxThreadCount, int maxMergeCount, int numProc) {
        Settings.Builder builder = Settings.builder().put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT);
        if (maxThreadCount != -1) {
            builder.put(MAX_THREAD_COUNT_SETTING.getKey(), maxThreadCount);
        }
        if (maxMergeCount != -1) {
            builder.put(MAX_MERGE_COUNT_SETTING.getKey(), maxMergeCount);
        }
        if (numProc != -1) {
            builder.put(NODE_PROCESSORS_SETTING.getKey(), numProc);
        }
        return newIndexMeta("index", builder.build());
    }

    public void testMaxThreadAndMergeCount() {
        IllegalArgumentException exc = expectThrows(
            IllegalArgumentException.class,
            () -> new MergeSchedulerConfig(new IndexSettings(createMetadata(10, 4, -1), Settings.EMPTY))
        );
        assertThat(exc.getMessage(), containsString("maxThreadCount (= 10) should be <= maxMergeCount (= 4)"));

        IndexSettings settings = new IndexSettings(createMetadata(-1, -1, 2), Settings.EMPTY);
        assertEquals(1, settings.getMergeSchedulerConfig().getMaxThreadCount());
        assertEquals(6, settings.getMergeSchedulerConfig().getMaxMergeCount());

        settings = new IndexSettings(createMetadata(4, 10, -1), Settings.EMPTY);
        assertEquals(4, settings.getMergeSchedulerConfig().getMaxThreadCount());
        assertEquals(10, settings.getMergeSchedulerConfig().getMaxMergeCount());
        IndexMetadata newMetadata = createMetadata(15, 20, -1);

        settings.updateIndexMetadata(newMetadata);
        assertEquals(15, settings.getMergeSchedulerConfig().getMaxThreadCount());
        assertEquals(20, settings.getMergeSchedulerConfig().getMaxMergeCount());

        settings.updateIndexMetadata(createMetadata(40, 50, -1));
        assertEquals(40, settings.getMergeSchedulerConfig().getMaxThreadCount());
        assertEquals(50, settings.getMergeSchedulerConfig().getMaxMergeCount());

        settings.updateIndexMetadata(createMetadata(40, -1, -1));
        assertEquals(40, settings.getMergeSchedulerConfig().getMaxThreadCount());
        assertEquals(45, settings.getMergeSchedulerConfig().getMaxMergeCount());

        final IndexSettings finalSettings = settings;
        exc = expectThrows(IllegalArgumentException.class, () -> finalSettings.updateIndexMetadata(createMetadata(40, 30, -1)));
        assertThat(exc.getMessage(), containsString("maxThreadCount (= 40) should be <= maxMergeCount (= 30)"));

        exc = expectThrows(IllegalArgumentException.class, () -> finalSettings.updateIndexMetadata(createMetadata(-1, 3, 8)));
        assertThat(exc.getMessage(), containsString("maxThreadCount (= 4) should be <= maxMergeCount (= 3)"));
    }
}
