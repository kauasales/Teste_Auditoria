/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.common.time;

import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

class Iso8601DateTimeParser implements DateTimeParser {

    private final Iso8601Parser parser;
    private final ZoneId timezone;
    // the locale doesn't actually matter, as we're parsing in a standardised format
    // and we already account for . or , in decimals
    private final Locale locale;

    Iso8601DateTimeParser(Set<ChronoField> mandatoryFields, boolean optionalTime) {
        parser = new Iso8601Parser(mandatoryFields, optionalTime, Map.of());
        timezone = null;
        locale = null;
    }

    private Iso8601DateTimeParser(Iso8601Parser parser, ZoneId timezone, Locale locale) {
        this.parser = parser;
        this.timezone = timezone;
        this.locale = locale;
    }

    @Override
    public ZoneId getZone() {
        return timezone;
    }

    @Override
    public Locale getLocale() {
        return locale;
    }

    @Override
    public DateTimeParser withZone(ZoneId zone) {
        return new Iso8601DateTimeParser(parser, zone, locale);
    }

    @Override
    public DateTimeParser withLocale(Locale locale) {
        return new Iso8601DateTimeParser(parser, timezone, locale);
    }

    Iso8601DateTimeParser withDefaults(Map<ChronoField, Integer> defaults) {
        return new Iso8601DateTimeParser(new Iso8601Parser(parser.mandatoryFields(), parser.optionalTime(), defaults), timezone, locale);
    }

    @Override
    public TemporalAccessor parse(CharSequence str) {
        var result = parser.tryParse(str, timezone);
        var temporal = result.result();
        if (temporal == null) {
            throw new DateTimeParseException("Could not fully parse datetime", str, result.errorIndex());
        }
        return temporal;
    }

    @Override
    public Optional<TemporalAccessor> tryParse(CharSequence str) {
        return Optional.ofNullable(parser.tryParse(str, timezone).result());
    }
}
