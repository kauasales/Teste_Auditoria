/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.ccr.action.bulk;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.replication.TransportWriteAction;
import org.elasticsearch.cluster.action.shard.ShardStateAction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.engine.Engine;
import org.elasticsearch.index.seqno.SeqNoStats;
import org.elasticsearch.index.seqno.SequenceNumbers;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.translog.Translog;
import org.elasticsearch.indices.IndicesService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.ccr.index.engine.AlreadyProcessedFollowingEngineException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class TransportBulkShardOperationsAction
        extends TransportWriteAction<BulkShardOperationsRequest, BulkShardOperationsRequest, BulkShardOperationsResponse> {

    @Inject
    public TransportBulkShardOperationsAction(
            final Settings settings,
            final TransportService transportService,
            final ClusterService clusterService,
            final IndicesService indicesService,
            final ThreadPool threadPool,
            final ShardStateAction shardStateAction,
            final ActionFilters actionFilters,
            final IndexNameExpressionResolver indexNameExpressionResolver) {
        super(
                settings,
                BulkShardOperationsAction.NAME,
                transportService,
                clusterService,
                indicesService,
                threadPool,
                shardStateAction,
                actionFilters,
                indexNameExpressionResolver,
                BulkShardOperationsRequest::new,
                BulkShardOperationsRequest::new,
                ThreadPool.Names.WRITE);
    }

    @Override
    protected WritePrimaryResult<BulkShardOperationsRequest, BulkShardOperationsResponse> shardOperationOnPrimary(
            final BulkShardOperationsRequest request, final IndexShard primary) throws Exception {
        return shardOperationOnPrimary(request.shardId(), request.getHistoryUUID(), request.getOperations(),
            request.getMaxSeqNoOfUpdatesOrDeletes(), primary, logger);
    }

    // public for testing purposes only
    public static CcrWritePrimaryResult shardOperationOnPrimary(
            final ShardId shardId,
            final String historyUUID,
            final List<Translog.Operation> sourceOperations,
            final long maxSeqNoOfUpdatesOrDeletes,
            final IndexShard primary,
            final Logger logger) throws IOException {
        if (historyUUID.equalsIgnoreCase(primary.getHistoryUUID()) == false) {
            throw new IllegalStateException("unexpected history uuid, expected [" + historyUUID +
                "], actual [" + primary.getHistoryUUID() + "], shard is likely restored from snapshot or force allocated");
        }

        final Function<Translog.Operation, Translog.Operation> rewriteWithTerm = operation -> {
            final Translog.Operation operationWithPrimaryTerm;
            switch (operation.opType()) {
                case INDEX:
                    final Translog.Index index = (Translog.Index) operation;
                    operationWithPrimaryTerm = new Translog.Index(
                            index.type(),
                            index.id(),
                            index.seqNo(),
                            primary.getOperationPrimaryTerm(),
                            index.version(),
                            index.versionType(),
                            BytesReference.toBytes(index.source()),
                            index.routing(),
                            index.parent(),
                            index.getAutoGeneratedIdTimestamp());
                    break;
                case DELETE:
                    final Translog.Delete delete = (Translog.Delete) operation;
                    operationWithPrimaryTerm = new Translog.Delete(
                            delete.type(),
                            delete.id(),
                            delete.uid(),
                            delete.seqNo(),
                            primary.getOperationPrimaryTerm(),
                            delete.version(),
                            delete.versionType());
                    break;
                case NO_OP:
                    final Translog.NoOp noOp = (Translog.NoOp) operation;
                    operationWithPrimaryTerm = new Translog.NoOp(noOp.seqNo(), primary.getOperationPrimaryTerm(), noOp.reason());
                    break;
                default:
                    throw new IllegalStateException("unexpected operation type [" + operation.opType() + "]");
            }
            return operationWithPrimaryTerm;
        };

        assert maxSeqNoOfUpdatesOrDeletes >= SequenceNumbers.NO_OPS_PERFORMED : "invalid msu [" + maxSeqNoOfUpdatesOrDeletes + "]";
        primary.advanceMaxSeqNoOfUpdatesOrDeletes(maxSeqNoOfUpdatesOrDeletes);

        final List<Translog.Operation> appliedOperations = new ArrayList<>(sourceOperations.size());
        Translog.Location location = null;
        long waitingForGlobalCheckpoint = SequenceNumbers.UNASSIGNED_SEQ_NO;
        for (Translog.Operation sourceOp : sourceOperations) {
            final Translog.Operation targetOp = rewriteWithTerm.apply(sourceOp);
            final Engine.Result result = primary.applyTranslogOperation(targetOp, Engine.Operation.Origin.PRIMARY);
            if (result.getResultType() == Engine.Result.Type.SUCCESS) {
                assert result.getSeqNo() == targetOp.seqNo();
                appliedOperations.add(targetOp);
                location = locationToSync(location, result.getTranslogLocation());
            } else {
                if (result.getFailure() instanceof AlreadyProcessedFollowingEngineException) {
                    // Skipped operations will be delivered to replicas via primary-replica resync or peer-recovery.
                    // The primary must not acknowledge this request until the global checkpoint is at least the highest
                    // seqno of all skipped operations (i.e., all skipped operations have been processed on every replica).
                    waitingForGlobalCheckpoint = SequenceNumbers.max(waitingForGlobalCheckpoint, targetOp.seqNo());
                } else {
                    assert false : "Only already-processed error should happen; op=[" + targetOp + "] error=[" + result.getFailure() + "]";
                    throw ExceptionsHelper.convertToElastic(result.getFailure());
                }
            }
        }
        assert appliedOperations.size() == sourceOperations.size() || waitingForGlobalCheckpoint != SequenceNumbers.UNASSIGNED_SEQ_NO :
            "waiting global checkpoint is not assigned; waiting_gcp=" + waitingForGlobalCheckpoint +
            " source_ops=" + sourceOperations.size() + " applied_ops=" + sourceOperations.size();
        assert appliedOperations.size() == 0 || location != null;
        final BulkShardOperationsRequest replicaRequest = new BulkShardOperationsRequest(
            shardId, historyUUID, appliedOperations, maxSeqNoOfUpdatesOrDeletes);
        return new CcrWritePrimaryResult(replicaRequest, location, primary, waitingForGlobalCheckpoint, logger);
    }

    @Override
    protected WriteReplicaResult<BulkShardOperationsRequest> shardOperationOnReplica(
            final BulkShardOperationsRequest request, final IndexShard replica) throws Exception {
        return shardOperationOnReplica(request, replica, logger);
    }

    // public for testing purposes only
    public static WriteReplicaResult<BulkShardOperationsRequest> shardOperationOnReplica(
        final BulkShardOperationsRequest request, final IndexShard replica, final Logger logger) throws IOException {
        assert replica.getMaxSeqNoOfUpdatesOrDeletes() >= request.getMaxSeqNoOfUpdatesOrDeletes() :
            "mus on replica [" + replica + "] < mus of request [" + request.getMaxSeqNoOfUpdatesOrDeletes() + "]";
        Translog.Location location = null;
        for (final Translog.Operation operation : request.getOperations()) {
            final Engine.Result result = replica.applyTranslogOperation(operation, Engine.Operation.Origin.REPLICA);
            if (result.getResultType() != Engine.Result.Type.SUCCESS) {
                assert false : "doc-level failure must not happen on replicas; op[" + operation + "] error[" + result.getFailure() + "]";
                throw ExceptionsHelper.convertToElastic(result.getFailure());
            }
            assert result.getSeqNo() == operation.seqNo();
            location = locationToSync(location, result.getTranslogLocation());
        }
        assert request.getOperations().size() == 0 || location != null;
        return new WriteReplicaResult<>(request, location, null, replica, logger);
    }

    @Override
    protected BulkShardOperationsResponse newResponseInstance() {
        return new BulkShardOperationsResponse();
    }

    /**
     * Custom write result to include global checkpoint after ops have been replicated.
     */
    static final class CcrWritePrimaryResult extends WritePrimaryResult<BulkShardOperationsRequest, BulkShardOperationsResponse> {
        final long waitingForGlobalCheckpoint;

        CcrWritePrimaryResult(BulkShardOperationsRequest request, Translog.Location location, IndexShard primary,
                              long waitingForGlobalCheckpoint, Logger logger) {
            super(request, new BulkShardOperationsResponse(), location, null, primary, logger);
            this.waitingForGlobalCheckpoint = waitingForGlobalCheckpoint;
        }

        @Override
        public synchronized void respond(ActionListener<BulkShardOperationsResponse> listener) {
            final ActionListener<BulkShardOperationsResponse> wrappedListener = ActionListener.wrap(response -> {
                final SeqNoStats seqNoStats = primary.seqNoStats();
                // return a fresh global checkpoint after the operations have been replicated for the shard follow task
                response.setGlobalCheckpoint(seqNoStats.getGlobalCheckpoint());
                response.setMaxSeqNo(seqNoStats.getMaxSeqNo());
                listener.onResponse(response);
            }, listener::onFailure);

            if (waitingForGlobalCheckpoint != SequenceNumbers.UNASSIGNED_SEQ_NO) {
                primary.addGlobalCheckpointListener(waitingForGlobalCheckpoint, (gcp, e) -> {
                    if (e != null) {
                        listener.onFailure(e);
                    } else {
                        assert waitingForGlobalCheckpoint <= gcp : waitingForGlobalCheckpoint + " > " + gcp;
                        super.respond(wrappedListener);
                    }
                }, null);
            } else {
                super.respond(wrappedListener);
            }
        }

    }

}
