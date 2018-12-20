/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ml.filestructurefinder;

import org.elasticsearch.ElasticsearchTimeoutException;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.common.util.concurrent.FutureUtils;
import org.elasticsearch.grok.Grok;
import org.elasticsearch.grok.ThreadWatchdog;

import java.io.Closeable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This class can be used to keep track of when a long running operation started and
 * to check whether it has run for longer than permitted.
 *
 * An object should be constructed at the beginning of the operation and then the
 * {@link #check} method called periodically during the processing of the operation.
 *
 * This class does not use the {@link Thread#interrupt} mechanism because some other
 * methods already convert interruptions to other types of exceptions (for example
 * {@link Grok#captures}) and this would lead to non-uniform exception types and
 * misleading error messages in the event that the interrupt was handled by one of
 * these methods.  The code in the long running operation would still have to
 * periodically call {@link Thread#interrupted}, so it is not much more of an
 * inconvenience to have to periodically call this class's {@link #check} method.
 */
public class TimeoutChecker implements Closeable {

    private static final TimeoutCheckerWatchdog timeoutCheckerWatchdog = new TimeoutCheckerWatchdog();
    public static final ThreadWatchdog watchdog = timeoutCheckerWatchdog;

    private final String operation;
    private final TimeValue timeout;
    private final Thread checkedThread;
    private final ScheduledFuture<?> future;
    private volatile boolean timeoutExceeded;

    /**
     * The constructor should be called at the start of the operation whose duration
     * is to be checked, as the timeout is measured relative to time of construction.
     * @param operation A description of the operation whose duration is to be checked.
     * @param timeout The timeout period.  If <code>null</code> then there is no timeout.
     * @param scheduler Used to schedule the timer.  This may be <code>null</code>
     *                  in the case where {@code timeout} is also <code>null</code>.
     */
    public TimeoutChecker(String operation, TimeValue timeout, ScheduledExecutorService scheduler) {
        this.operation = operation;
        this.timeout = timeout;
        this.checkedThread = Thread.currentThread();
        timeoutCheckerWatchdog.add(checkedThread, timeout);
        this.future = (timeout != null) ? scheduler.schedule(this::setTimeoutExceeded, timeout.nanos(), TimeUnit.NANOSECONDS) : null;
    }

    /**
     * Stops the timer if running.
     */
    @Override
    public void close() {
        FutureUtils.cancel(future);
        timeoutCheckerWatchdog.remove(checkedThread);
    }

    /**
     * Check whether the operation has been running longer than the permitted time.
     * @param where Which stage of the operation is currently in progress?
     * @throws ElasticsearchTimeoutException If the operation is found to have taken longer than the permitted time.
     */
    public void check(String where) {

        if (timeoutExceeded) {
            throw new ElasticsearchTimeoutException("Aborting " + operation + " during [" + where +
                "] as it has taken longer than the timeout of [" + timeout + "]");
        }
    }

    /**
     * Wrapper around {@link Grok#captures} that translates any timeout exception
     * to the style thrown by this class's {@link #check} method.
     * @param grok The grok pattern from which captures are to be extracted.
     * @param text The text to match and extract values from.
     * @param where Which stage of the operation is currently in progress?
     * @return A map containing field names and their respective coerced values that matched.
     * @throws ElasticsearchTimeoutException If the operation is found to have taken longer than the permitted time.
     */
    public Map<String, Object> grokCaptures(Grok grok, String text, String where) {

        try {
            return grok.captures(text);
        } finally {
            // If a timeout has occurred then this check will overwrite any timeout exception thrown by Grok.captures() and this
            // is intentional - the exception from this class makes more sense in the context of the find file structure API
            check(where);
        }
    }

    private void setTimeoutExceeded() {
        timeoutExceeded = true;
        timeoutCheckerWatchdog.interruptLongRunningThreadIfRegistered(checkedThread);
    }

    /**
     * An implementation of the type of watchdog used by the {@link Grok} class to interrupt
     * matching operations that take too long.  Rather than have a timeout per match operation
     * like the {@link ThreadWatchdog.Default} implementation, the interruption is governed by
     * a {@link TimeoutChecker} associated with the thread doing the matching.
     */
    static class TimeoutCheckerWatchdog implements ThreadWatchdog {

        final ConcurrentHashMap<Thread, Tuple<AtomicBoolean, TimeValue>> registry = new ConcurrentHashMap<>();

        void add(Thread thread, TimeValue timeout) {
            Tuple<AtomicBoolean, TimeValue> previousValue = registry.put(thread, new Tuple<>(new AtomicBoolean(false), timeout));
            assert previousValue == null;
        }

        @Override
        public void register() {
            Tuple<AtomicBoolean, TimeValue> value = registry.get(Thread.currentThread());
            if (value != null) {
                boolean wasFalse = value.v1().compareAndSet(false, true);
                assert wasFalse;
            }
        }

        @Override
        public long maxExecutionTimeInMillis() {
            Tuple<AtomicBoolean, TimeValue> value = registry.get(Thread.currentThread());
            return value != null ? value.v2().getMillis() : Long.MAX_VALUE;
        }

        @Override
        public void unregister() {
            Tuple<AtomicBoolean, TimeValue> value = registry.get(Thread.currentThread());
            if (value != null) {
                boolean wasTrue = value.v1().compareAndSet(true, false);
                assert wasTrue;
            }
        }

        void remove(Thread thread) {
            Tuple<AtomicBoolean, TimeValue> previousValue = registry.remove(thread);
            assert previousValue != null;
        }

        void interruptLongRunningThreadIfRegistered(Thread thread) {
            Tuple<AtomicBoolean, TimeValue> value = registry.get(thread);
            if (value.v1().get()) {
                thread.interrupt();
            }
        }
    }
}
