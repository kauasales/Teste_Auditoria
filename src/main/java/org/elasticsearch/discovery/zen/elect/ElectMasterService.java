/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
 * file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.discovery.zen.elect;

import com.google.common.collect.Lists;
import org.elasticsearch.cluster.metadata.MetaData;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.component.AbstractComponent;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.node.settings.NodeSettingsService;

import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
public class ElectMasterService extends AbstractComponent {

    static {
        MetaData.addDynamicSettings("discovery.zen.minimum_master_nodes");
    }

    private final NodeComparator nodeComparator = new NodeComparator();

    private volatile int minimumMasterNodes;

    public ElectMasterService(Settings settings, NodeSettingsService nodeSettingsService) {
        super(settings);
        this.minimumMasterNodes = settings.getAsInt("discovery.zen.minimum_master_nodes", -1);
        logger.debug("using minimum_master_nodes [{}]", minimumMasterNodes);
        nodeSettingsService.addListener(new ApplySettings());
    }

    public boolean hasEnoughMasterNodes(Iterable<DiscoveryNode> nodes) {
        if (minimumMasterNodes < 1) {
            return true;
        }
        int count = 0;
        for (DiscoveryNode node : nodes) {
            if (node.masterNode()) {
                count++;
            }
        }
        return count >= minimumMasterNodes;
    }

    /**
     * Returns a list of the next possible masters.
     */
    public DiscoveryNode[] nextPossibleMasters(Iterable<DiscoveryNode> nodes, int numberOfPossibleMasters) {
        List<DiscoveryNode> sortedNodes = sortedMasterNodes(nodes);
        if (sortedNodes == null) {
            return new DiscoveryNode[0];
        }
        List<DiscoveryNode> nextPossibleMasters = Lists.newArrayListWithCapacity(numberOfPossibleMasters);
        int counter = 0;
        for (DiscoveryNode nextPossibleMaster : sortedNodes) {
            if (++counter >= numberOfPossibleMasters) {
                break;
            }
            nextPossibleMasters.add(nextPossibleMaster);
        }
        return nextPossibleMasters.toArray(new DiscoveryNode[nextPossibleMasters.size()]);
    }

    /**
     * Elects a new master out of the possible nodes, returning it. Returns <tt>null</tt>
     * if no master has been elected.
     */
    public DiscoveryNode electMaster(Iterable<DiscoveryNode> nodes) {
        List<DiscoveryNode> sortedNodes = sortedMasterNodes(nodes);
        if (sortedNodes == null || sortedNodes.isEmpty()) {
            return null;
        }
        return sortedNodes.get(0);
    }

    private List<DiscoveryNode> sortedMasterNodes(Iterable<DiscoveryNode> nodes) {
        List<DiscoveryNode> possibleNodes = Lists.newArrayList(nodes);
        if (possibleNodes.isEmpty()) {
            return null;
        }
        // clean non master nodes
        for (Iterator<DiscoveryNode> it = possibleNodes.iterator(); it.hasNext(); ) {
            DiscoveryNode node = it.next();
            if (!node.masterNode()) {
                it.remove();
            }
        }
        Collections.sort(possibleNodes, nodeComparator);
        return possibleNodes;
    }

    class ApplySettings implements NodeSettingsService.Listener {
        @Override
        public void onRefreshSettings(Settings settings) {
            int minimumMasterNodes = settings.getAsInt("discovery.zen.minimum_master_nodes", ElectMasterService.this.minimumMasterNodes);
            if (minimumMasterNodes != ElectMasterService.this.minimumMasterNodes) {
                logger.info("updating [discovery.zen.minimum_master_nodes] from [{}] to [{}]", ElectMasterService.this.minimumMasterNodes, minimumMasterNodes);
                ElectMasterService.this.minimumMasterNodes = minimumMasterNodes;
            }
        }
    }

    private static class NodeComparator implements Comparator<DiscoveryNode> {

        @Override
        public int compare(DiscoveryNode o1, DiscoveryNode o2) {
            return o1.id().compareTo(o2.id());
        }
    }
}
