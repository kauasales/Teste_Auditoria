/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package org.elasticsearch.search.aggregations.bucket.range;

import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.search.DocValueFormat;
import org.elasticsearch.search.aggregations.AggregationReduceContext;
import org.elasticsearch.search.aggregations.InternalAggregation;
import org.elasticsearch.search.aggregations.InternalAggregations;
import org.elasticsearch.search.aggregations.InternalMultiBucketAggregation;
import org.elasticsearch.search.aggregations.support.CoreValuesSourceType;
import org.elasticsearch.search.aggregations.support.ValueType;
import org.elasticsearch.search.aggregations.support.ValuesSourceType;
import org.elasticsearch.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class InternalRange<B extends InternalRange.Bucket, R extends InternalRange<B, R>> extends InternalMultiBucketAggregation<R, B>
    implements
        Range {
    @SuppressWarnings("rawtypes")
    static final Factory FACTORY = new Factory();

    public static class Bucket extends InternalMultiBucketAggregation.InternalBucket implements Range.Bucket {

        protected final transient boolean keyed;
        protected final transient DocValueFormat format;
        protected final double from;
        protected final double originalFrom;
        protected final double to;
        protected final double originalTo;
        private final long docCount;
        private final InternalAggregations aggregations;
        private final String key;

        public Bucket(
            String key,
            double from,
            double originalFrom,
            double to,
            double originalTo,
            long docCount,
            InternalAggregations aggregations,
            boolean keyed,
            DocValueFormat format
        ) {
            this.keyed = keyed;
            this.format = format;
            this.key = key != null ? key : generateKey(originalFrom, originalTo, format);
            this.from = from;
            this.originalFrom = originalFrom;
            this.to = to;
            this.originalTo = originalTo;
            this.docCount = docCount;
            this.aggregations = aggregations;
        }

        @Override
        public String getKey() {
            return getKeyAsString();
        }

        @Override
        public String getKeyAsString() {
            return key;
        }

        @Override
        public Object getFrom() {
            return from;
        }

        public double getOriginalFrom() {
            return originalFrom;
        }

        @Override
        public Object getTo() {
            return to;
        }

        public double getOriginalTo() {
            return originalTo;
        }

        public boolean getKeyed() {
            return keyed;
        }

        public DocValueFormat getFormat() {
            return format;
        }

        @Override
        public String getFromAsString() {
            if (Double.isInfinite(originalFrom)) {
                return null;
            } else {
                return format.format(originalFrom).toString();
            }
        }

        @Override
        public String getToAsString() {
            if (Double.isInfinite(originalTo)) {
                return null;
            } else {
                return format.format(originalTo).toString();
            }
        }

        @Override
        public long getDocCount() {
            return docCount;
        }

        @Override
        public InternalAggregations getAggregations() {
            return aggregations;
        }

        @SuppressWarnings("unchecked")
        protected Factory<? extends Bucket, ?> getFactory() {
            return FACTORY;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            if (keyed) {
                builder.startObject(key);
            } else {
                builder.startObject();
                builder.field(CommonFields.KEY.getPreferredName(), key);
            }
            if (Double.isInfinite(originalFrom) == false) {
                builder.field(CommonFields.FROM.getPreferredName(), originalFrom);
                if (format != DocValueFormat.RAW) {
                    builder.field(CommonFields.FROM_AS_STRING.getPreferredName(), format.format(originalFrom));
                }
            }
            if (Double.isInfinite(originalTo) == false) {
                builder.field(CommonFields.TO.getPreferredName(), originalTo);
                if (format != DocValueFormat.RAW) {
                    builder.field(CommonFields.TO_AS_STRING.getPreferredName(), format.format(originalTo));
                }
            }
            builder.field(CommonFields.DOC_COUNT.getPreferredName(), docCount);
            aggregations.toXContentInternal(builder, params);
            builder.endObject();
            return builder;
        }

        private static String generateKey(double from, double to, DocValueFormat format) {
            StringBuilder builder = new StringBuilder().append(Double.isInfinite(from) ? "*" : format.format(from))
                .append("-")
                .append(Double.isInfinite(to) ? "*" : format.format(to));
            return builder.toString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(key);
            out.writeDouble(from);
            if (out.getVersion().onOrAfter(Version.V_8_1_0)) {
                out.writeDouble(originalFrom);
            }
            out.writeDouble(to);
            if (out.getVersion().onOrAfter(Version.V_8_1_0)) {
                out.writeDouble(originalTo);
            }
            out.writeVLong(docCount);
            aggregations.writeTo(out);
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (other == null || getClass() != other.getClass()) {
                return false;
            }
            Bucket that = (Bucket) other;
            return Objects.equals(from, that.from)
                && Objects.equals(to, that.to)
                && Objects.equals(docCount, that.docCount)
                && Objects.equals(aggregations, that.aggregations)
                && Objects.equals(key, that.key);
        }

        @Override
        public int hashCode() {
            return Objects.hash(getClass(), from, to, docCount, aggregations, key);
        }
    }

    public static class Factory<B extends Bucket, R extends InternalRange<B, R>> {
        public ValuesSourceType getValueSourceType() {
            return CoreValuesSourceType.NUMERIC;
        }

        public ValueType getValueType() {
            return ValueType.NUMERIC;
        }

        @SuppressWarnings("unchecked")
        public R create(String name, List<B> ranges, DocValueFormat format, boolean keyed, Map<String, Object> metadata) {
            return (R) new InternalRange<B, R>(name, ranges, format, keyed, metadata);
        }

        @SuppressWarnings("unchecked")
        public B createBucket(
            String key,
            double from,
            double originalFrom,
            double to,
            double originalTo,
            long docCount,
            InternalAggregations aggregations,
            boolean keyed,
            DocValueFormat format
        ) {
            return (B) new Bucket(key, from, originalFrom, to, originalTo, docCount, aggregations, keyed, format);
        }

        @SuppressWarnings("unchecked")
        public R create(List<B> ranges, R prototype) {
            return (R) new InternalRange<B, R>(prototype.name, ranges, prototype.format, prototype.keyed, prototype.metadata);
        }

        @SuppressWarnings("unchecked")
        public B createBucket(InternalAggregations aggregations, B prototype) {
            return (B) new Bucket(
                prototype.getKey(),
                prototype.from,
                prototype.originalFrom,
                prototype.to,
                prototype.originalTo,
                prototype.getDocCount(),
                aggregations,
                prototype.keyed,
                prototype.format
            );
        }
    }

    private final List<B> ranges;
    protected final DocValueFormat format;
    protected final boolean keyed;

    public InternalRange(String name, List<B> ranges, DocValueFormat format, boolean keyed, Map<String, Object> metadata) {
        super(name, metadata);
        this.ranges = ranges;
        this.format = format;
        this.keyed = keyed;
    }

    /**
     * Read from a stream.
     */
    public InternalRange(StreamInput in) throws IOException {
        super(in);
        format = in.readNamedWriteable(DocValueFormat.class);
        keyed = in.readBoolean();
        int size = in.readVInt();
        List<B> ranges = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            String key = in.readString();
            double from = in.readDouble();
            double originalFrom = in.getVersion().onOrAfter(Version.V_8_1_0) ? in.readDouble() : from;
            double to = in.readDouble();
            double originalTo = in.getVersion().onOrAfter(Version.V_8_1_0) ? in.readDouble() : to;
            long docCount = in.readVLong();
            ranges.add(
                getFactory().createBucket(
                    key,
                    from,
                    originalFrom,
                    to,
                    originalTo,
                    docCount,
                    InternalAggregations.readFrom(in),
                    keyed,
                    format
                )
            );
        }
        this.ranges = ranges;
    }

    @Override
    protected void doWriteTo(StreamOutput out) throws IOException {
        out.writeNamedWriteable(format);
        out.writeBoolean(keyed);
        out.writeVInt(ranges.size());
        for (B bucket : ranges) {
            bucket.writeTo(out);
        }
    }

    @Override
    public String getWriteableName() {
        return RangeAggregationBuilder.NAME;
    }

    @Override
    public List<B> getBuckets() {
        return ranges;
    }

    @SuppressWarnings("unchecked")
    public Factory<B, R> getFactory() {
        return FACTORY;
    }

    @SuppressWarnings("unchecked")
    @Override
    public R create(List<B> buckets) {
        return getFactory().create(buckets, (R) this);
    }

    @Override
    public B createBucket(InternalAggregations aggregations, B prototype) {
        return getFactory().createBucket(aggregations, prototype);
    }

    @SuppressWarnings("unchecked")
    @Override
    public InternalAggregation reduce(List<InternalAggregation> aggregations, AggregationReduceContext reduceContext) {
        reduceContext.consumeBucketsAndMaybeBreak(ranges.size());
        @SuppressWarnings("rawtypes")
        List<B>[] rangeList = new List[ranges.size()];
        for (int i = 0; i < rangeList.length; ++i) {
            rangeList[i] = new ArrayList<>();
        }
        for (InternalAggregation aggregation : aggregations) {
            InternalRange<B, R> ranges = (InternalRange<B, R>) aggregation;
            int i = 0;
            for (B range : ranges.ranges) {
                rangeList[i++].add(range);
            }
        }

        final List<B> ranges = new ArrayList<>();
        for (int i = 0; i < this.ranges.size(); ++i) {
            ranges.add(reduceBucket(rangeList[i], reduceContext));
        }
        return getFactory().create(name, ranges, format, keyed, getMetadata());
    }

    @Override
    protected B reduceBucket(List<B> buckets, AggregationReduceContext context) {
        assert buckets.size() > 0;
        long docCount = 0;
        List<InternalAggregations> aggregationsList = new ArrayList<>(buckets.size());
        for (Bucket bucket : buckets) {
            docCount += bucket.docCount;
            aggregationsList.add(bucket.aggregations);
        }
        final InternalAggregations aggs = InternalAggregations.reduce(aggregationsList, context);
        Bucket prototype = buckets.get(0);
        return getFactory().createBucket(
            prototype.key,
            prototype.from,
            prototype.originalFrom,
            prototype.to,
            prototype.originalTo,
            docCount,
            aggs,
            keyed,
            format
        );
    }

    @Override
    public XContentBuilder doXContentBody(XContentBuilder builder, Params params) throws IOException {
        if (keyed) {
            builder.startObject(CommonFields.BUCKETS.getPreferredName());
        } else {
            builder.startArray(CommonFields.BUCKETS.getPreferredName());
        }
        for (B range : ranges) {
            range.toXContent(builder, params);
        }
        if (keyed) {
            builder.endObject();
        } else {
            builder.endArray();
        }
        return builder;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), ranges, format, keyed);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        if (super.equals(obj) == false) return false;

        InternalRange<?, ?> that = (InternalRange<?, ?>) obj;
        return Objects.equals(ranges, that.ranges) && Objects.equals(format, that.format) && Objects.equals(keyed, that.keyed);
    }
}
