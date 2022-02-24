/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.common.cli;

import org.elasticsearch.common.logging.LogSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.logging.Level;
import org.elasticsearch.logging.internal.LogConfigurator;

/**
 * Holder class for method to configure logging without Elasticsearch configuration files for use in CLI tools that will not read such
 * files.
 */
public final class CommandLoggingConfigurator {

    /**
     * Configures logging without Elasticsearch configuration files based on the system property "es.logger.level" only. As such, any
     * logging will be written to the console.
     */
    public static void configureLoggingWithoutConfig() {
        // initialize default for es.logger.level because we will not read the log4j2.properties
        final String loggerLevel = System.getProperty("es.logger.level", Level.INFO.name());
        final Settings settings = Settings.builder().put("logger.level", loggerLevel).build();
        LogConfigurator.configureWithoutConfig(LogSettings.defaultLogLevel(settings), LogSettings.logLevelSettingsMap(settings));
    }

}
