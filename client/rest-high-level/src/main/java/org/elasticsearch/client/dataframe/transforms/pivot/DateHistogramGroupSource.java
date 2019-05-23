/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.client.dataframe.transforms.pivot;

import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ObjectParser;
import org.elasticsearch.common.xcontent.ToXContentFragment;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogramInterval;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * A grouping via a date histogram aggregation referencing a timefield
 */
public class DateHistogramGroupSource extends SingleGroupSource implements ToXContentObject {

    private static final ParseField TIME_ZONE = new ParseField("time_zone");
    private static final ParseField FORMAT = new ParseField("format");

    // From DateHistogramAggregationBuilder in core, transplanted and modified to a set
    // so we don't need to import a dependency on the class
    private static final Set<String> DATE_FIELD_UNITS;
    static {
        Set<String> dateFieldUnits = new HashSet<>();
        dateFieldUnits.add("year");
        dateFieldUnits.add("1y");
        dateFieldUnits.add("quarter");
        dateFieldUnits.add("1q");
        dateFieldUnits.add("month");
        dateFieldUnits.add("1M");
        dateFieldUnits.add("week");
        dateFieldUnits.add("1w");
        dateFieldUnits.add("day");
        dateFieldUnits.add("1d");
        dateFieldUnits.add("hour");
        dateFieldUnits.add("1h");
        dateFieldUnits.add("minute");
        dateFieldUnits.add("1m");
        dateFieldUnits.add("second");
        dateFieldUnits.add("1s");
        DATE_FIELD_UNITS = Collections.unmodifiableSet(dateFieldUnits);
    }

    public interface Interval extends ToXContentFragment {

    }

    public static class FixedInterval implements Interval {
        private static final String NAME = "fixed_interval";
        private final DateHistogramInterval interval;

        public FixedInterval(DateHistogramInterval interval) {
            this.interval = interval;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.field(NAME, interval.toString());
            return builder;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }

            if (other == null || getClass() != other.getClass()) {
                return false;
            }

            final FixedInterval that = (FixedInterval) other;

            return Objects.equals(this.interval, that.interval);
        }

        @Override
        public int hashCode() {
            return Objects.hash(interval);
        }
    }

    public static class CalendarInterval implements Interval {
        private static final String NAME = "calendar_interval";
        private final DateHistogramInterval interval;

        public CalendarInterval(DateHistogramInterval interval) {
            this.interval = interval;
            if (DATE_FIELD_UNITS.contains(interval.toString()) == false) {
                throw new IllegalArgumentException("The supplied interval [" + interval +"] could not be parsed " +
                    "as a calendar interval.");
            }
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.field(NAME, interval.toString());
            return builder;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }

            if (other == null || getClass() != other.getClass()) {
                return false;
            }

            final CalendarInterval that = (CalendarInterval) other;

            return Objects.equals(this.interval, that.interval);
        }

        @Override
        public int hashCode() {
            return Objects.hash(interval);
        }
    }

    private static final ConstructingObjectParser<DateHistogramGroupSource, Void> PARSER =
            new ConstructingObjectParser<>("date_histogram_group_source",
                true,
                (args) -> {
                   String field = (String)args[0];
                   String fixedInterval = (String) args[1];
                   String calendarInterval = (String) args[2];

                   Interval interval = null;

                   if (fixedInterval != null && calendarInterval != null) {
                       throw new IllegalArgumentException("You must specify either fixed_interval or calendar_interval, found none");
                   } else if (fixedInterval != null) {
                       interval = new FixedInterval(new DateHistogramInterval(fixedInterval));
                   } else if (calendarInterval != null) {
                       interval = new CalendarInterval(new DateHistogramInterval(calendarInterval));
                   } else {
                       throw new IllegalArgumentException("You must specify either fixed_interval or calendar_interval, found both");
                   }

                   ZoneId zoneId = (ZoneId) args[3];
                   String format = (String) args[4];
                   return new DateHistogramGroupSource(field, interval, format, zoneId);
                });

    static {
        PARSER.declareString(optionalConstructorArg(), FIELD);

        PARSER.declareString(optionalConstructorArg(), new ParseField(FixedInterval.NAME));
        PARSER.declareString(optionalConstructorArg(), new ParseField(CalendarInterval.NAME));

        PARSER.declareField(optionalConstructorArg(), p -> {
            if (p.currentToken() == XContentParser.Token.VALUE_STRING) {
                return ZoneId.of(p.text());
            } else {
                return ZoneOffset.ofHours(p.intValue());
            }
        }, TIME_ZONE, ObjectParser.ValueType.LONG);

        PARSER.declareString(optionalConstructorArg(), FORMAT);
    }

    public static DateHistogramGroupSource fromXContent(final XContentParser parser) {
        return PARSER.apply(parser, null);
    }

    private final Interval interval;
    private final String format;
    private final ZoneId timeZone;

    DateHistogramGroupSource(String field, Interval interval, String format, ZoneId timeZone) {
        super(field);
        this.interval = interval;
        this.format = format;
        this.timeZone = timeZone;
    }

    @Override
    public Type getType() {
        return Type.DATE_HISTOGRAM;
    }

    public Interval getInterval() {
        return interval;
    }

    public String getFormat() {
        return format;
    }

    public ZoneId getTimeZone() {
        return timeZone;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (field != null) {
            builder.field(FIELD.getPreferredName(), field);
        }
        interval.toXContent(builder, params);
        if (timeZone != null) {
            builder.field(TIME_ZONE.getPreferredName(), timeZone.toString());
        }
        if (format != null) {
            builder.field(FORMAT.getPreferredName(), format);
        }
        builder.endObject();
        return builder;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (other == null || getClass() != other.getClass()) {
            return false;
        }

        final DateHistogramGroupSource that = (DateHistogramGroupSource) other;

        return Objects.equals(this.field, that.field) &&
                Objects.equals(interval, that.interval) &&
                Objects.equals(timeZone, that.timeZone) &&
                Objects.equals(format, that.format);
    }

    @Override
    public int hashCode() {
        return Objects.hash(field, interval, timeZone, format);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String field;
        private Interval interval;
        private String format;
        private ZoneId timeZone;

        /**
         * The field with which to construct the date histogram grouping
         * @param field The field name
         * @return The {@link Builder} with the field set.
         */
        public Builder setField(String field) {
            this.field = field;
            return this;
        }

        /**
         * Set the interval for the DateHistogram grouping
         * @param interval a fixed or calendar interval
         * @return the {@link Builder} with the interval set.
         */
        public Builder setInterval(Interval interval) {
            this.interval = interval;
            return this;
        }

        /**
         * Set the optional String formatting for the time interval.
         * @param format The format of the output for the time interval key
         * @return The {@link Builder} with the format set.
         */
        public Builder setFormat(String format) {
            this.format = format;
            return this;
        }

        /**
         * Sets the time zone to use for this aggregation
         * @param timeZone The zoneId for the timeZone
         * @return The {@link Builder} with the timeZone set.
         */
        public Builder setTimeZone(ZoneId timeZone) {
            this.timeZone = timeZone;
            return this;
        }

        public DateHistogramGroupSource build() {
            return new DateHistogramGroupSource(field, interval, format, timeZone);
        }
    }
}
