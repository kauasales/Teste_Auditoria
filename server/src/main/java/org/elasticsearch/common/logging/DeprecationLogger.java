/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.common.logging;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.util.concurrent.ThreadContext;

/**
 * A logger that logs deprecation notices.
 */
public class DeprecationLogger {
    private final ThrottlingAndHeaderWarningLogger deprecationLogger;

    /**
     * Creates a new deprecation logger based on the parent logger. Automatically
     * prefixes the logger name with "deprecation", if it starts with "org.elasticsearch.",
     * it replaces "org.elasticsearch" with "org.elasticsearch.deprecation" to maintain
     * the "org.elasticsearch" namespace.
     */
    public DeprecationLogger(Logger parentLogger) {
        deprecationLogger = new ThrottlingAndHeaderWarningLogger(deprecatedLoggerName(parentLogger));
    }

    private static Logger deprecatedLoggerName(Logger parentLogger) {
        String name = parentLogger.getName();
        if (name.startsWith("org.elasticsearch")) {
            name = name.replace("org.elasticsearch.", "org.elasticsearch.deprecation.");
        } else {
            name = "deprecation." + name;
        }
        return LogManager.getLogger(name);
    }

    public static void setThreadContext(ThreadContext threadContext) {
        HeaderWarningLogger.setThreadContext(threadContext);
    }

    public static void removeThreadContext(ThreadContext threadContext) {
        HeaderWarningLogger.removeThreadContext(threadContext);
    }

    /**
     * Logs a deprecation message, adding a formatted warning message as a response header on the thread context.
     */
    //TODO fix logger usage check
    public DeprecationLoggerBuilder deprecate(final String key, final String msg, final Object... params) {
        return new DeprecationLoggerBuilder()
            .withDeprecation(key, msg, params);
    }

    public class DeprecationLoggerBuilder {

        private String deprecationKey;
        private ESLogMessage deprecationMessage;

        public DeprecationLoggerBuilder withDeprecation(String key, String msg, Object[] params) {
            this.deprecationKey = key;
            String opaqueId = HeaderWarningLogger.getXOpaqueId();
            this.deprecationMessage = DeprecatedMessage.of(opaqueId, msg, params);
            return this;
        }

        public void log() {
            deprecationLogger.throttleLogAndAddWarning(deprecationKey, deprecationMessage);
        }
    }
}
