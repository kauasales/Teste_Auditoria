/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.monitoring.collector.indices;

import org.elasticsearch.action.admin.indices.recovery.RecoveryAction;
import org.elasticsearch.action.admin.indices.recovery.RecoveryRequestBuilder;
import org.elasticsearch.action.admin.indices.recovery.RecoveryResponse;
import org.elasticsearch.client.AdminClient;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.ElasticsearchClient;
import org.elasticsearch.client.IndicesAdminClient;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.routing.RecoverySource;
import org.elasticsearch.cluster.routing.ShardRouting;
import org.elasticsearch.cluster.routing.UnassignedInfo;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.TimeValue;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.indices.recovery.RecoveryState;
import org.elasticsearch.xpack.core.monitoring.MonitoredSystem;
import org.elasticsearch.xpack.core.monitoring.exporter.MonitoringDoc;
import org.elasticsearch.xpack.monitoring.BaseCollectorTestCase;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.elasticsearch.xpack.monitoring.MonitoringTestUtils.randomMonitoringNode;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class IndexRecoveryCollectorTests extends BaseCollectorTestCase {

    public void testShouldCollectReturnsFalseIfMonitoringNotAllowed() {
        // this controls the blockage
        when(licenseState.isMonitoringAllowed()).thenReturn(false);
        final boolean isElectedMaster = randomBoolean();
        whenLocalNodeElectedMaster(isElectedMaster);

        final IndexRecoveryCollector collector = new IndexRecoveryCollector(Settings.EMPTY, clusterService, monitoringService,
                                                                            licenseState, client);

        assertThat(collector.shouldCollect(isElectedMaster), is(false));
        if (isElectedMaster) {
            verify(licenseState).isMonitoringAllowed();
        }
    }

    public void testShouldCollectReturnsFalseIfNotMaster() {
        when(licenseState.isMonitoringAllowed()).thenReturn(true);
        final IndexRecoveryCollector collector = new IndexRecoveryCollector(Settings.EMPTY, clusterService, monitoringService,
                                                                            licenseState, client);

        assertThat(collector.shouldCollect(false), is(false));
    }

    public void testShouldCollectReturnsFalseIfElasticsearchCollectionIsDisabled() {
        when(monitoringService.isElasticsearchCollectionEnabled()).thenReturn(false);
        when(licenseState.isMonitoringAllowed()).thenReturn(true);
        final boolean isElectedMaster = randomBoolean();
        whenLocalNodeElectedMaster(isElectedMaster);

        final IndexRecoveryCollector collector =
            new IndexRecoveryCollector(Settings.EMPTY, clusterService, monitoringService, licenseState, client);
        assertThat(collector.shouldCollect(isElectedMaster), is(false));
    }

    public void testShouldCollectReturnsTrue() {
        when(monitoringService.isElasticsearchCollectionEnabled()).thenReturn(true);
        when(licenseState.isMonitoringAllowed()).thenReturn(true);
        final IndexRecoveryCollector collector = new IndexRecoveryCollector(Settings.EMPTY, clusterService, monitoringService,
                                                                            licenseState, client);

        assertThat(collector.shouldCollect(true), is(true));
        verify(licenseState).isMonitoringAllowed();
    }

    public void testDoCollect() throws Exception {
        final TimeValue timeout = TimeValue.timeValueSeconds(randomIntBetween(1, 120));
        withCollectionTimeout(IndexRecoveryCollector.INDEX_RECOVERY_TIMEOUT, timeout);

        whenLocalNodeElectedMaster(true);

        final String clusterName = randomAlphaOfLength(10);
        whenClusterStateWithName(clusterName);

        final String clusterUUID = UUID.randomUUID().toString();
        whenClusterStateWithUUID(clusterUUID);

        final DiscoveryNode localNode = localNode(randomAlphaOfLength(5));
        when(clusterService.localNode()).thenReturn(localNode);

        final MonitoringDoc.Node node = randomMonitoringNode(random());

        final boolean recoveryOnly = randomBoolean();
        withCollectionSetting(builder -> builder.put(IndexRecoveryCollector.INDEX_RECOVERY_ACTIVE_ONLY.getKey(), recoveryOnly));

        final String[] indices;
        if (randomBoolean()) {
            indices = randomBoolean() ? null : Strings.EMPTY_ARRAY;
        } else {
            indices = new String[randomIntBetween(1, 5)];
            for (int i = 0; i < indices.length; i++) {
                indices[i] = randomAlphaOfLengthBetween(5, 10);
            }
        }
        withCollectionIndices(indices);

        final int nbRecoveries = randomBoolean() ? 0 : randomIntBetween(1, 3);
        final Map<String, List<RecoveryState>> recoveryStates = new HashMap<>();
        for (int i = 0; i < nbRecoveries; i++) {
            ShardId shardId = new ShardId("_index_" + i, "_uuid_" + i, i);
            RecoverySource source = RecoverySource.PeerRecoverySource.INSTANCE;
            final UnassignedInfo unassignedInfo = new UnassignedInfo(UnassignedInfo.Reason.INDEX_CREATED, "_index_info_" + i);
            final ShardRouting shardRouting = ShardRouting
                                                .newUnassigned(shardId, true, source, unassignedInfo)
                                                .initialize(localNode.getId(), "_allocation_id", 10 * i);

            final RecoveryState recoveryState = new RecoveryState(shardRouting, localNode, localNode);
            recoveryStates.put("_index_" + i, singletonList(recoveryState));
        }
        final RecoveryResponse recoveryResponse =
                new RecoveryResponse(randomInt(), randomInt(), randomInt(), recoveryStates, emptyList());

        final RecoveryRequestBuilder recoveryRequestBuilder =
                spy(new RecoveryRequestBuilder(mock(ElasticsearchClient.class), RecoveryAction.INSTANCE));
        doReturn(recoveryResponse).when(recoveryRequestBuilder).get(eq(timeout));

        final IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        when(indicesAdminClient.prepareRecoveries()).thenReturn(recoveryRequestBuilder);

        final AdminClient adminClient = mock(AdminClient.class);
        when(adminClient.indices()).thenReturn(indicesAdminClient);

        final Client client = mock(Client.class);
        when(client.admin()).thenReturn(adminClient);

        final IndexRecoveryCollector collector = new IndexRecoveryCollector(Settings.EMPTY, clusterService, monitoringService,
                                                                            licenseState, client);
        assertEquals(timeout, collector.getCollectionTimeout());
        assertEquals(recoveryOnly, collector.getActiveRecoveriesOnly());

        if (indices != null) {
            assertArrayEquals(indices, collector.getCollectionIndices());
        } else {
            // Collection indices has a default value equals to emptyList(),
            // so it won't return a null indices array
            assertArrayEquals(Strings.EMPTY_ARRAY, collector.getCollectionIndices());
        }

        final long interval = randomNonNegativeLong();

        final Collection<MonitoringDoc> results = collector.doCollect(node, interval, clusterState);
        verify(indicesAdminClient).prepareRecoveries();
        if (recoveryStates.isEmpty() == false) {
            verify(clusterState).metaData();
            verify(metaData).clusterUUID();
        }

        if (nbRecoveries == 0) {
            assertEquals(0, results.size());
        } else {
            assertEquals(1, results.size());

            final MonitoringDoc monitoringDoc = results.iterator().next();
            assertThat(monitoringDoc, instanceOf(IndexRecoveryMonitoringDoc.class));

            final IndexRecoveryMonitoringDoc document = (IndexRecoveryMonitoringDoc) monitoringDoc;
            assertThat(document.getCluster(), equalTo(clusterUUID));
            assertThat(document.getTimestamp(), greaterThan(0L));
            assertThat(document.getIntervalMillis(), equalTo(interval));
            assertThat(document.getNode(), equalTo(node));
            assertThat(document.getSystem(), is(MonitoredSystem.ES));
            assertThat(document.getType(), equalTo(IndexRecoveryMonitoringDoc.TYPE));
            assertThat(document.getId(), nullValue());

            final RecoveryResponse recoveries = document.getRecoveryResponse();
            assertThat(recoveries, notNullValue());
            assertThat(recoveries.hasRecoveries(), equalTo(true));
            assertThat(recoveries.shardRecoveryStates().size(), equalTo(nbRecoveries));
        }
    }
}
