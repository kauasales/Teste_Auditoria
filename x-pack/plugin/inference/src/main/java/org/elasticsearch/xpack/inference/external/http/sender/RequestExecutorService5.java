/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.inference.external.http.sender;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ContextPreservingActionListener;
import org.elasticsearch.common.util.concurrent.EsRejectedExecutionException;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.Strings;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.inference.InferenceServiceResults;
import org.elasticsearch.threadpool.Scheduler;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.inference.common.AdjustableCapacityBlockingQueue;
import org.elasticsearch.xpack.inference.common.RateLimiter;
import org.elasticsearch.xpack.inference.external.http.retry.RequestSender;
import org.elasticsearch.xpack.inference.services.settings.RateLimitSettings;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.elasticsearch.core.Strings.format;
import static org.elasticsearch.xpack.inference.InferencePlugin.UTILITY_THREAD_POOL_NAME;

class RequestExecutorService5 {

    private static final AdjustableCapacityBlockingQueue.QueueCreator<RejectableTask> QUEUE_CREATOR =
        new AdjustableCapacityBlockingQueue.QueueCreator<>() {
            @Override
            public BlockingQueue<RejectableTask> create(int capacity) {
                BlockingQueue<RejectableTask> queue;
                if (capacity <= 0) {
                    queue = create();
                } else {
                    queue = new LinkedBlockingQueue<>(capacity);
                }

                return queue;
            }

            @Override
            public BlockingQueue<RejectableTask> create() {
                return new LinkedBlockingQueue<>();
            }
        };

    private static final TimeValue DEFAULT_CLEANUP_INTERVAL = TimeValue.timeValueDays(10);
    private static final Duration DEFAULT_STALE_DURATION = Duration.ofDays(10);

    private static final Logger logger = LogManager.getLogger(RequestExecutorService5.class);

    private final ConcurrentMap<Object, RateLimitingEndpointHandler> inferenceEndpoints = new ConcurrentHashMap<>();
    private final ThreadPool threadPool;
    private final CountDownLatch startupLatch;
    private final CountDownLatch terminationLatch = new CountDownLatch(1);
    private final RequestSender requestSender;
    private final RequestExecutorServiceSettings settings;
    private final TimeValue cleanUpInterval;
    private final Duration staleEndpointDuration;
    private final Clock clock;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);
    private final AdjustableCapacityBlockingQueue.QueueCreator<RejectableTask> queueCreator;

    RequestExecutorService5(
        ThreadPool threadPool,
        @Nullable CountDownLatch startupLatch,
        RequestExecutorServiceSettings settings,
        RequestSender requestSender
    ) {
        this(
            threadPool,
            QUEUE_CREATOR,
            startupLatch,
            settings,
            requestSender,
            DEFAULT_CLEANUP_INTERVAL,
            DEFAULT_STALE_DURATION,
            Clock.systemUTC()
        );
    }

    RequestExecutorService5(
        ThreadPool threadPool,
        AdjustableCapacityBlockingQueue.QueueCreator<RejectableTask> queueCreator,
        @Nullable CountDownLatch startupLatch,
        RequestExecutorServiceSettings settings,
        RequestSender requestSender,
        TimeValue cleanUpInterval,
        Duration staleEndpointDuration,
        Clock clock
    ) {
        this.threadPool = Objects.requireNonNull(threadPool);
        this.queueCreator = Objects.requireNonNull(queueCreator);
        this.startupLatch = startupLatch;
        this.requestSender = Objects.requireNonNull(requestSender);
        this.settings = Objects.requireNonNull(settings);
        this.cleanUpInterval = Objects.requireNonNull(cleanUpInterval);
        this.staleEndpointDuration = Objects.requireNonNull(staleEndpointDuration);
        this.clock = Objects.requireNonNull(clock);
    }

    public void shutdown() {
        if (shutdown.compareAndSet(false, true)) {
            for (var endpoint : inferenceEndpoints.values()) {
                endpoint.shutdown();
            }
        }
    }

    public boolean isShutdown() {
        return shutdown.get();
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return terminationLatch.await(timeout, unit);
    }

    public boolean isTerminated() {
        return terminationLatch.getCount() == 0;
    }

    public int queueSize() {
        return inferenceEndpoints.values().stream().mapToInt(RateLimitingEndpointHandler::queueSize).sum();
    }

    public void start() {
        try {
            signalStartInitiated();

            while (isShutdown() == false) {
                handleTasks();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            shutdown();
            notifyRequestsOfShutdown();
            terminationLatch.countDown();
        }
    }

    private void signalStartInitiated() {
        if (startupLatch != null) {
            startupLatch.countDown();
        }
    }

    private void handleTasks() throws InterruptedException {
        boolean handledAtLeastOneTask = false;
        for (var endpoint : inferenceEndpoints.values()) {
            handledAtLeastOneTask |= endpoint.executeEnqueuedTask();
        }

        if (handledAtLeastOneTask == false) {
            // TODO make this configurable
            Thread.sleep(50);
        }
    }

    private void notifyRequestsOfShutdown() {
        assert isShutdown() : "Requests should only be notified if the executor is shutting down";

        for (var endpoint : inferenceEndpoints.values()) {
            endpoint.notifyRequestsOfShutdown();
        }
    }

    /**
     * Execute the request at some point in the future.
     *
     * @param requestCreator the http request to send
     * @param inferenceInputs the inputs to send in the request
     * @param timeout the maximum time to wait for this request to complete (failing or succeeding). Once the time elapses, the
     *                listener::onFailure is called with a {@link org.elasticsearch.ElasticsearchTimeoutException}.
     *                If null, then the request will wait forever
     * @param listener an {@link ActionListener<InferenceServiceResults>} for the response or failure
     */
    public void execute(
        RequestManager requestCreator,
        InferenceInputs inferenceInputs,
        @Nullable TimeValue timeout,
        ActionListener<InferenceServiceResults> listener
    ) {
        var task = new RequestTask(
            requestCreator,
            inferenceInputs,
            timeout,
            threadPool,
            // TODO when multi-tenancy (as well as batching) is implemented we need to be very careful that we preserve
            // the thread contexts correctly to avoid accidentally retrieving the credentials for the wrong user
            ContextPreservingActionListener.wrapPreservingContext(listener, threadPool.getThreadContext())
        );

        var endpoint = inferenceEndpoints.computeIfAbsent(
            requestCreator.rateLimitGrouping(),
            key -> new RateLimitingEndpointHandler(
                Integer.toString(requestCreator.rateLimitGrouping().hashCode()),
                queueCreator,
                settings,
                requestSender,
                clock,
                requestCreator.rateLimitSettings()
            )
        );

        endpoint.enqueue(task);
    }

    // TODO schedule a cleanup thread to run on an interval and remove entries from the map that are over a day old
    private Scheduler.Cancellable startCleanUpThread(ThreadPool threadPool) {
        logger.debug(() -> Strings.format("Clean up task scheduled with interval [%s]", cleanUpInterval));

        return threadPool.scheduleWithFixedDelay(this::removeOldEndpoints, cleanUpInterval, threadPool.executor(UTILITY_THREAD_POOL_NAME));
    }

    private void removeOldEndpoints() {
        var now = Instant.now(clock);
        // if the current time is after the last time the endpoint received a request + allowed stale period then we'll remove it
        inferenceEndpoints.entrySet()
            .removeIf(endpoint -> now.isAfter(endpoint.getValue().timeOfLastEnqueue().plus(staleEndpointDuration)));
    }

    /**
     * Provides a mechanism for ensuring that only a single thread is processing tasks from the queue at a time.
     * As tasks are enqueued for execution, if a thread executing (or scheduled to execute a task in the future),
     * a new one will not be started.
     */
    private static class RateLimitingEndpointHandler {

        private static final Logger logger = LogManager.getLogger(RateLimitingEndpointHandler.class);

        private final AdjustableCapacityBlockingQueue<RejectableTask> queue;
        private final AtomicBoolean shutdown = new AtomicBoolean();
        private final RequestSender requestSender;
        private final String id;
        private Instant timeOfLastEnqueue;
        private final Clock clock;
        private final RateLimiter rateLimiter;

        RateLimitingEndpointHandler(
            String id,
            AdjustableCapacityBlockingQueue.QueueCreator<RejectableTask> createQueue,
            RequestExecutorServiceSettings settings,
            RequestSender requestSender,
            Clock clock,
            RateLimitSettings rateLimitSettings
        ) {
            this.id = Objects.requireNonNull(id);
            this.queue = new AdjustableCapacityBlockingQueue<>(createQueue, settings.getQueueCapacity());
            this.requestSender = Objects.requireNonNull(requestSender);
            this.clock = Objects.requireNonNull(clock);

            Objects.requireNonNull(rateLimitSettings);
            // TODO figure out a good limit
            rateLimiter = new RateLimiter(1, rateLimitSettings.requestsPerTimeUnit(), rateLimitSettings.timeUnit());

            settings.registerQueueCapacityCallback(this::onCapacityChange);
        }

        private void onCapacityChange(int capacity) {
            logger.debug(() -> Strings.format("Executor service [%s] setting queue capacity to [%s]", id, capacity));

            try {
                queue.setCapacity(capacity);
            } catch (Exception e) {
                logger.warn(format("Executor service [%s] failed to set the capacity of the task queue to [%s]", id, capacity), e);
            }
        }

        public int queueSize() {
            return queue.size();
        }

        public void shutdown() {
            shutdown.set(true);
        }

        public boolean isShutdown() {
            return shutdown.get();
        }

        public Instant timeOfLastEnqueue() {
            return timeOfLastEnqueue;
        }

        public synchronized boolean executeEnqueuedTask() {
            var timeBeforeAvailableToken = rateLimiter.timeToReserve2(1);
            var task = queue.poll();

            if (shouldExecuteImmediately(timeBeforeAvailableToken) == false || task == null) {
                return false;
            }

            executeTask(task);
            return true;
        }

        private static boolean shouldExecuteImmediately(TimeValue delay) {
            return delay.duration() == 0;
        }

        public void enqueue(RequestTask task) {
            timeOfLastEnqueue = Instant.now(clock);

            if (isShutdown()) {
                EsRejectedExecutionException rejected = new EsRejectedExecutionException(
                    format(
                        "Failed to enqueue task because the executor service [%s] has already shutdown",
                        task.getRequestManager().inferenceEntityId()
                    ),
                    true
                );

                task.onRejection(rejected);
                return;
            }

            var addedToQueue = queue.offer(task);

            if (addedToQueue == false) {
                EsRejectedExecutionException rejected = new EsRejectedExecutionException(
                    format(
                        "Failed to execute task because the executor service [%s] queue is full",
                        task.getRequestManager().inferenceEntityId()
                    ),
                    false
                );

                task.onRejection(rejected);
            } else if (isShutdown()) {
                notifyRequestsOfShutdown();
            }
        }

        private void executeTask(RejectableTask task) {
            try {
                if (isNoopRequest(task) || task.hasCompleted()) {
                    return;
                }

                task.getRequestManager().execute(task.getInput(), requestSender, task.getRequestCompletedFunction(), task.getListener());
            } catch (Exception e) {
                logger.warn(
                    format(
                        "Executor service [%s] failed to execute request for inference endpoint id [%s]",
                        id,
                        task.getRequestManager().inferenceEntityId()
                    ),
                    e
                );
            }
        }

        private static boolean isNoopRequest(InferenceRequest inferenceRequest) {
            return inferenceRequest.getRequestManager() == null
                || inferenceRequest.getInput() == null
                || inferenceRequest.getListener() == null;
        }

        public synchronized void notifyRequestsOfShutdown() {
            assert isShutdown() : "Requests should only be notified if the executor is shutting down";

            try {
                List<RejectableTask> notExecuted = new ArrayList<>();
                queue.drainTo(notExecuted);

                rejectTasks(notExecuted);
            } catch (Exception e) {
                logger.warn(format("Failed to notify tasks of queuing service [%s] shutdown", id));
            }
        }

        private void rejectTasks(List<RejectableTask> tasks) {
            for (var task : tasks) {
                rejectTask(task);
            }
        }

        private void rejectTask(RejectableTask task) {
            try {
                task.onRejection(
                    new EsRejectedExecutionException(
                        format(
                            "Failed to send request, queue service for inference entity [%s] has shutdown prior to executing request",
                            task.getRequestManager().inferenceEntityId()
                        ),
                        true
                    )
                );
            } catch (Exception e) {
                logger.warn(
                    format(
                        "Failed to notify request for inference endpoint [%s] of rejection after queuing service shutdown",
                        task.getRequestManager().inferenceEntityId()
                    )
                );
            }
        }

    }
}
