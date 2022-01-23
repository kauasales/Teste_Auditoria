/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.ingest;

import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.util.Maps;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.xcontent.ToXContentFragment;
import org.elasticsearch.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class IngestStats implements Writeable, ToXContentFragment {
    private final Stats totalStats;
    private final List<PipelineStat> pipelineStats;
    private final Map<String, List<ProcessorStat>> processorStats;

    /**
     * @param totalStats - The total stats for Ingest. This is the logically the sum of all pipeline stats,
     *                   and pipeline stats are logically the sum of the processor stats.
     * @param pipelineStats - The stats for a given ingest pipeline.
     * @param processorStats - The per-processor stats for a given pipeline. A map keyed by the pipeline identifier.
     */
    public IngestStats(Stats totalStats, List<PipelineStat> pipelineStats, Map<String, List<ProcessorStat>> processorStats) {
        this.totalStats = totalStats;
        this.pipelineStats = pipelineStats;
        this.processorStats = processorStats;
    }

    /**
     * Read from a stream.
     */
    public IngestStats(StreamInput in) throws IOException {
        this.totalStats = new Stats(in);
        int size = in.readVInt();
        this.pipelineStats = new ArrayList<>(size);
        this.processorStats = Maps.newMapWithExpectedSize(size);
        for (int i = 0; i < size; i++) {
            String pipelineId = in.readString();
            Stats pipelineStat = new Stats(in);
            this.pipelineStats.add(new PipelineStat(pipelineId, pipelineStat));
            int processorsSize = in.readVInt();
            List<ProcessorStat> processorStatsPerPipeline = new ArrayList<>(processorsSize);
            for (int j = 0; j < processorsSize; j++) {
                String processorName = in.readString();
                String processorType = in.readString();
                Stats processorStat = new Stats(in);
                processorStatsPerPipeline.add(new ProcessorStat(processorName, processorType, processorStat));
            }
            this.processorStats.put(pipelineId, processorStatsPerPipeline);
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        totalStats.writeTo(out);
        out.writeVInt(pipelineStats.size());
        for (PipelineStat pipelineStat : pipelineStats) {
            out.writeString(pipelineStat.pipelineId());
            pipelineStat.stats().writeTo(out);
            List<ProcessorStat> processorStatsForPipeline = processorStats.get(pipelineStat.pipelineId());
            if (processorStatsForPipeline == null) {
                out.writeVInt(0);
            } else {
                out.writeVInt(processorStatsForPipeline.size());
                for (ProcessorStat processorStat : processorStatsForPipeline) {
                    out.writeString(processorStat.name());
                    out.writeString(processorStat.type());
                    processorStat.stats().writeTo(out);
                }
            }
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject("ingest");
        builder.startObject("total");
        totalStats.toXContent(builder, params);
        builder.endObject();
        builder.startObject("pipelines");
        for (PipelineStat pipelineStat : pipelineStats) {
            builder.startObject(pipelineStat.pipelineId());
            pipelineStat.stats().toXContent(builder, params);
            List<ProcessorStat> processorStatsForPipeline = processorStats.get(pipelineStat.pipelineId());
            builder.startArray("processors");
            if (processorStatsForPipeline != null) {
                for (ProcessorStat processorStat : processorStatsForPipeline) {
                    builder.startObject();
                    builder.startObject(processorStat.name());
                    builder.field("type", processorStat.type());
                    builder.startObject("stats");
                    processorStat.stats().toXContent(builder, params);
                    builder.endObject();
                    builder.endObject();
                    builder.endObject();
                }
            }
            builder.endArray();
            builder.endObject();
        }
        builder.endObject();
        builder.endObject();
        return builder;
    }

    public Stats getTotalStats() {
        return totalStats;
    }

    public List<PipelineStat> getPipelineStats() {
        return pipelineStats;
    }

    public Map<String, List<ProcessorStat>> getProcessorStats() {
        return processorStats;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IngestStats that = (IngestStats) o;
        return Objects.equals(totalStats, that.totalStats)
            && Objects.equals(pipelineStats, that.pipelineStats)
            && Objects.equals(processorStats, that.processorStats);
    }

    @Override
    public int hashCode() {
        return Objects.hash(totalStats, pipelineStats, processorStats);
    }

    public static class Stats implements Writeable, ToXContentFragment {

        private final long ingestCount;
        private final long ingestTimeInMillis;
        private final long ingestCurrent;
        private final long ingestFailedCount;

        public Stats(long ingestCount, long ingestTimeInMillis, long ingestCurrent, long ingestFailedCount) {
            this.ingestCount = ingestCount;
            this.ingestTimeInMillis = ingestTimeInMillis;
            this.ingestCurrent = ingestCurrent;
            this.ingestFailedCount = ingestFailedCount;
        }

        /**
         * Read from a stream.
         */
        public Stats(StreamInput in) throws IOException {
            ingestCount = in.readVLong();
            ingestTimeInMillis = in.readVLong();
            ingestCurrent = in.readVLong();
            ingestFailedCount = in.readVLong();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeVLong(ingestCount);
            out.writeVLong(ingestTimeInMillis);
            out.writeVLong(ingestCurrent);
            out.writeVLong(ingestFailedCount);
        }

        /**
         * @return The total number of executed ingest preprocessing operations.
         */
        public long getIngestCount() {
            return ingestCount;
        }

        /**
         * @return The total time spent of ingest preprocessing in millis.
         */
        public long getIngestTimeInMillis() {
            return ingestTimeInMillis;
        }

        /**
         * @return The total number of ingest preprocessing operations currently executing.
         */
        public long getIngestCurrent() {
            return ingestCurrent;
        }

        /**
         * @return The total number of ingest preprocessing operations that have failed.
         */
        public long getIngestFailedCount() {
            return ingestFailedCount;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.field("count", ingestCount);
            builder.humanReadableField("time_in_millis", "time", new TimeValue(ingestTimeInMillis, TimeUnit.MILLISECONDS));
            builder.field("current", ingestCurrent);
            builder.field("failed", ingestFailedCount);
            return builder;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            IngestStats.Stats that = (IngestStats.Stats) o;
            return Objects.equals(ingestCount, that.ingestCount)
                && Objects.equals(ingestTimeInMillis, that.ingestTimeInMillis)
                && Objects.equals(ingestFailedCount, that.ingestFailedCount)
                && Objects.equals(ingestCurrent, that.ingestCurrent);
        }

        @Override
        public int hashCode() {
            return Objects.hash(ingestCount, ingestTimeInMillis, ingestFailedCount, ingestCurrent);
        }
    }

    /**
     * Easy conversion from scoped {@link IngestMetric} objects to a serializable Stats objects
     */
    static class Builder {
        private Stats totalStats;
        private List<PipelineStat> pipelineStats = new ArrayList<>();
        private Map<String, List<ProcessorStat>> processorStats = new HashMap<>();

        Builder addTotalMetrics(IngestMetric totalMetric) {
            this.totalStats = totalMetric.createStats();
            return this;
        }

        Builder addPipelineMetrics(String pipelineId, IngestMetric pipelineMetric) {
            this.pipelineStats.add(new PipelineStat(pipelineId, pipelineMetric.createStats()));
            return this;
        }

        Builder addProcessorMetrics(String pipelineId, String processorName, String processorType, IngestMetric metric) {
            this.processorStats.computeIfAbsent(pipelineId, k -> new ArrayList<>())
                .add(new ProcessorStat(processorName, processorType, metric.createStats()));
            return this;
        }

        IngestStats build() {
            return new IngestStats(totalStats, Collections.unmodifiableList(pipelineStats), Collections.unmodifiableMap(processorStats));
        }
    }

    /**
     * Container for pipeline stats.
     */
    public record PipelineStat(String pipelineId, Stats stats) {}

    /**
     * Container for processor stats.
     */
    public record ProcessorStat(String name, String type, Stats stats) {}
}
