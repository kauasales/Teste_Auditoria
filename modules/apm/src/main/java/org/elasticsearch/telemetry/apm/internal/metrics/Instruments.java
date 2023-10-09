/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.telemetry.apm.internal.metrics;

import io.opentelemetry.api.metrics.Meter;

import org.elasticsearch.common.util.concurrent.ConcurrentCollections;
import org.elasticsearch.common.util.concurrent.ReleasableLock;
import org.elasticsearch.telemetry.metric.DoubleCounter;
import org.elasticsearch.telemetry.metric.DoubleGauge;
import org.elasticsearch.telemetry.metric.DoubleHistogram;
import org.elasticsearch.telemetry.metric.DoubleUpDownCounter;
import org.elasticsearch.telemetry.metric.LongCounter;
import org.elasticsearch.telemetry.metric.LongGauge;
import org.elasticsearch.telemetry.metric.LongHistogram;
import org.elasticsearch.telemetry.metric.LongUpDownCounter;

import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Container for registering and fetching instruments by type and name.
 * Instrument names must be unique for a given type on registration.
 * {@link #setProvider(Meter)} is used to change the provider for all existing instruments.
 */
public class Instruments {
    private final Registrar<DoubleCounterAdapter> doubleCounters = new Registrar<>();
    private final Registrar<DoubleUpDownCounterAdapter> doubleUpDownCounters = new Registrar<>();
    private final Registrar<DoubleGaugeAdapter> doubleGauges = new Registrar<>();
    private final Registrar<DoubleHistogramAdapter> doubleHistograms = new Registrar<>();
    private final Registrar<LongCounterAdapter> longCounters = new Registrar<>();
    private final Registrar<LongUpDownCounterAdapter> longUpDownCounters = new Registrar<>();
    private final Registrar<LongGaugeAdapter> longGauges = new Registrar<>();
    private final Registrar<LongHistogramAdapter> longHistograms = new Registrar<>();

    private final Meter meter;

    public Instruments(Meter meter) {
        this.meter = meter;
    }

    private final List<Registrar<?>> registrars = List.of(
        doubleCounters,
        doubleUpDownCounters,
        doubleGauges,
        doubleHistograms,
        longCounters,
        longUpDownCounters,
        longGauges,
        longHistograms
    );

    // Access to registration has to be restricted when the provider is updated in ::setProvider
    protected final ReleasableLock registerLock = new ReleasableLock(new ReentrantLock());

    public <T> DoubleCounter registerDoubleCounter(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return doubleCounters.register(new DoubleCounterAdapter(meter, name, description, unit));
        }
    }

    public DoubleCounter getDoubleCounter(String name) {
        return doubleCounters.get(name);
    }

    public <T> DoubleUpDownCounter registerDoubleUpDownCounter(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return doubleUpDownCounters.register(new DoubleUpDownCounterAdapter(meter, name, description, unit));
        }
    }

    public DoubleUpDownCounter getDoubleUpDownCounter(String name) {
        return doubleUpDownCounters.get(name);
    }

    public <T> DoubleGauge registerDoubleGauge(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return doubleGauges.register(new DoubleGaugeAdapter(meter, name, description, unit));
        }
    }

    public DoubleGauge getDoubleGauge(String name) {
        return doubleGauges.get(name);
    }

    public <T> DoubleHistogram registerDoubleHistogram(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return doubleHistograms.register(new DoubleHistogramAdapter(meter, name, description, unit));
        }
    }

    public DoubleHistogram getDoubleHistogram(String name) {
        return doubleHistograms.get(name);
    }

    public <T> LongCounter registerLongCounter(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return longCounters.register(new LongCounterAdapter(meter, name, description, unit));
        }
    }

    public LongCounter getLongCounter(String name) {
        return longCounters.get(name);
    }

    public <T> LongUpDownCounter registerLongUpDownCounter(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return longUpDownCounters.register(new LongUpDownCounterAdapter(meter, name, description, unit));
        }
    }

    public LongUpDownCounter getLongUpDownCounter(String name) {
        return longUpDownCounters.get(name);
    }

    public <T> LongGauge registerLongGauge(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return longGauges.register(new LongGaugeAdapter(meter, name, description, unit));
        }
    }

    public LongGauge getLongGauge(String name) {
        return longGauges.get(name);
    }

    public <T> LongHistogram registerLongHistogram(String name, String description, String unit) {
        try (ReleasableLock lock = registerLock.acquire()) {
            return longHistograms.register(new LongHistogramAdapter(meter, name, description, unit));
        }
    }

    public LongHistogram getLongHistogram(String name) {
        return longHistograms.get(name);
    }

    public void setProvider(Meter meter) {
        try (ReleasableLock lock = registerLock.acquire()) {
            for (Registrar<?> registrar : registrars) {
                registrar.setProvider(meter);
            }
        }
    }

    /**
     * A typed wrapper for a instrument that
     * @param <T>
     */
    private static class Registrar<T extends AbstractInstrument<?>> {
        private final Map<String, T> registered = ConcurrentCollections.newConcurrentMap();

        T register(T instrument) {
            registered.compute(instrument.getName(), (k, v) -> {
                if (v != null) {
                    throw new IllegalStateException(
                        instrument.getClass().getSimpleName() + "[" + instrument.getName() + "] already registered"
                    );
                }

                return instrument;
            });
            return instrument;
        }

        T get(String name) {
            return registered.get(name);
        }

        void setProvider(Meter meter) {
            registered.forEach((k, v) -> v.setProvider(meter));
        }
    }

    // scope for testing
    Meter getMeter() {
        return meter;
    }
}
