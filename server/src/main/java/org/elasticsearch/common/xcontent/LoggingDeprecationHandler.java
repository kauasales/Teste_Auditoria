/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.common.xcontent;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.TriConsumer;
import org.elasticsearch.common.logging.DeprecationCategory;
import org.elasticsearch.common.logging.DeprecationLogger;

import java.util.function.Supplier;

/**
 * Logs deprecations to the {@link DeprecationLogger}.
 * <p>
 * This is core's primary implementation of {@link DeprecationHandler} and
 * should <strong>absolutely</strong> be used everywhere where it parses
 * requests. It is much less appropriate when parsing responses from external
 * sources because it will report deprecated fields back to the user as
 * though the user sent them.
 */
public class LoggingDeprecationHandler implements DeprecationHandler {
    /**
     * The logger to which to send deprecation messages.
     * <p>
     * This uses ParseField's logger because that is the logger that
     * we have been using for many releases for deprecated fields.
     * Changing that will require some research to make super duper
     * sure it is safe.
     */
    private static final DeprecationLogger deprecationLogger = DeprecationLogger.getLogger(ParseField.class);

    public static final LoggingDeprecationHandler INSTANCE = new LoggingDeprecationHandler();

    private TriConsumer<String, Object[], String> deprecationLoggerFunction = (message, params, field_name) ->
        deprecationLogger.deprecate(DeprecationCategory.API, "deprecated_field_" + field_name, message, params);

    private TriConsumer<String, Object[], String> compatibleLoggerFunction = (message, params, field_name) ->
        deprecationLogger.compatibleApiWarning("deprecated_field_" + field_name, message, params);

    private LoggingDeprecationHandler() {
        // one instance only
    }

    @Override
    public void usedDeprecatedName(String parserName, Supplier<XContentLocation> location, String usedName, String modernName) {
        usedDeprecatedName(parserName, location, usedName, modernName, false);
    }

    @Override
    public void usedDeprecatedField(String parserName, Supplier<XContentLocation> location, String usedName, String replacedWith) {
        usedDeprecatedField(parserName, location, usedName, replacedWith, false);
    }

    @Override
    public void usedDeprecatedField(String parserName, Supplier<XContentLocation> location, String usedName) {
        usedDeprecatedField(parserName, location, usedName, false);
    }

    @Override
    public void usedDeprecatedName(String parserName, Supplier<XContentLocation> location, String usedName, String modernName,
                                   boolean isCompatibleDeprecation) {
        String prefix = parserLocation(parserName, location);
        TriConsumer<String, Object[], String> loggingFunction = getLoggingFunction(isCompatibleDeprecation);
        loggingFunction.apply("{}Deprecated field [{}] used, expected [{}] instead",
            new Object[]{prefix, usedName, modernName}, usedName);
    }

    @Override
    public void usedDeprecatedField(String parserName, Supplier<XContentLocation> location, String usedName, String replacedWith,
                                    boolean isCompatibleDeprecation) {
        String prefix = parserLocation(parserName, location);
        TriConsumer<String, Object[], String> loggingFunction = getLoggingFunction(isCompatibleDeprecation);
        loggingFunction.apply("{}Deprecated field [{}] used, replaced by [{}]",
            new Object[]{prefix, usedName, replacedWith}, usedName);
    }

    @Override
    public void usedDeprecatedField(String parserName, Supplier<XContentLocation> location, String usedName,
                                    boolean isCompatibleDeprecation) {
        String prefix = parserLocation(parserName, location);
        TriConsumer<String, Object[], String> loggingFunction = getLoggingFunction(isCompatibleDeprecation);
        loggingFunction.apply("{}Deprecated field [{}] used, this field is unused and will be removed entirely",
            new Object[]{prefix, usedName}, usedName);

    }

    private String parserLocation(String parserName, Supplier<XContentLocation> location) {
        return parserName == null ? "" : "[" + parserName + "][" + location.get() + "] ";
    }

    private TriConsumer<String, Object[], String> getLoggingFunction(boolean isCompatibleDeprecation) {
        if (isCompatibleDeprecation) {
            return compatibleLoggerFunction;
        } else {
            return deprecationLoggerFunction;
        }
    }
}
