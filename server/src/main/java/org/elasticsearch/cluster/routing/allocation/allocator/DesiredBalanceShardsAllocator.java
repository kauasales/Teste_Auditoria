/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.cluster.routing.allocation.allocator;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.routing.RerouteService;
import org.elasticsearch.cluster.routing.ShardRouting;
import org.elasticsearch.cluster.routing.allocation.RoutingAllocation;
import org.elasticsearch.cluster.routing.allocation.ShardAllocationDecision;
import org.elasticsearch.cluster.service.MasterService;
import org.elasticsearch.common.Priority;
import org.elasticsearch.threadpool.ThreadPool;

import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * A {@link ShardsAllocator} which asynchronously refreshes the desired balance held by the {@link DesiredBalanceService} and then takes
 * steps towards the desired balance using the {@link DesiredBalanceReconciler}.
 */
public class DesiredBalanceShardsAllocator implements ShardsAllocator {

    private final ShardsAllocator delegateAllocator;
    private final ContinuousComputation<DesiredBalanceInput> desiredBalanceComputation;
    private final DesiredBalanceService desiredBalanceService;
    private volatile boolean pendingReroute;

    private record DesiredBalancesListener(long index, ActionListener<Void> listener) {}

    private final AtomicLong indexGenerator = new AtomicLong(0);
    private final Deque<DesiredBalancesListener> pendingListeners = new LinkedList<>();

    public DesiredBalanceShardsAllocator(
        ShardsAllocator delegateAllocator,
        ThreadPool threadPool,
        Supplier<RerouteService> rerouteServiceSupplier
    ) {
        this.delegateAllocator = delegateAllocator;
        this.desiredBalanceService = new DesiredBalanceService(delegateAllocator);
        this.desiredBalanceComputation = new ContinuousComputation<>(threadPool.generic()) {
            @Override
            protected void processInput(DesiredBalanceInput desiredBalanceInput) {
                if (desiredBalanceService.updateDesiredBalanceAndReroute(desiredBalanceInput, this::isFresh)) {
                    pendingReroute = true;
                    boolean isFreshInput = isFresh(desiredBalanceInput);
                    var listener = new ActionListener<ClusterState>() {
                        @Override
                        public void onResponse(ClusterState clusterState) {
                            if (isFreshInput) {
                                pendingReroute = false;
                                triggerProcessedListeners(desiredBalanceInput.index());
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            //TODO check exception type?
                            triggerAllListenersFailure(e);
                        }
                    };
                    rerouteServiceSupplier.get().reroute("desired balance changed", Priority.NORMAL, listener);
                }
            }

            private void triggerProcessedListeners(long index) {
                synchronized (pendingListeners) {
                    while (true) {
                        var trigger = pendingListeners.peekFirst();
                        if (trigger == null || trigger.index > index) {
                            break;
                        }
                        pendingListeners.pollFirst().listener.onResponse(null);
                    }
                }
            }

            private void triggerAllListenersFailure(Exception e) {
                synchronized (pendingListeners) {
                    DesiredBalancesListener listener;
                    while ((listener = pendingListeners.pollLast()) != null) {
                        listener.listener.onFailure(e);
                    }
                }
            }

            @Override
            public String toString() {
                return "DesiredBalanceShardsAllocator#updateDesiredBalanceAndReroute";
            }
        };
    }

    @Override
    public void allocate(RoutingAllocation allocation) {
        allocate(allocation, ActionListener.noop());
    }

    @Override
    public void allocate(RoutingAllocation allocation, ActionListener<Void> listener) {
        assert MasterService.isMasterUpdateThread() || Thread.currentThread().getName().startsWith("TEST-")
            : Thread.currentThread().getName();
        // assert allocation.debugDecision() == false; set to true when called via the reroute API
        assert allocation.ignoreDisable() == false;

        // TODO must also capture any shards that the existing-shards allocators have allocated this pass, not just the ignored ones

        var index = indexGenerator.incrementAndGet();
        synchronized (pendingListeners) {
            pendingListeners.addLast(new DesiredBalancesListener(index, listener));
        }
        desiredBalanceComputation.onNewInput(
            new DesiredBalanceInput(index, allocation.immutableClone(), new ArrayList<>(allocation.routingNodes().unassigned().ignored()))
        );

        // TODO possibly add a bounded wait for the computation to complete?
        // Otherwise we will have to do a second cluster state update straight away.

        new DesiredBalanceReconciler(getCurrentDesiredBalance(), allocation).run();

    }

    @Override
    public ShardAllocationDecision decideShardAllocation(ShardRouting shard, RoutingAllocation allocation) {
        return delegateAllocator.decideShardAllocation(shard, allocation);
    }

    DesiredBalance getCurrentDesiredBalance() {
        return desiredBalanceService.getCurrentDesiredBalance();
    }

    public boolean isIdle() {
        return desiredBalanceComputation.isActive() == false && pendingReroute == false;
    }
}
