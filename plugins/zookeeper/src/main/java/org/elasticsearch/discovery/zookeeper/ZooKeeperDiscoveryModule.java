/*
 * Licensed to Elastic Search and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Elastic Search licenses this
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

package org.elasticsearch.discovery.zookeeper;

import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.discovery.Discovery;
import org.elasticsearch.zookeeper.ZooKeeperClient;
import org.elasticsearch.zookeeper.ZooKeeperClientService;
import org.elasticsearch.zookeeper.ZooKeeperEnvironment;
import org.elasticsearch.zookeeper.ZooKeeperFactory;


/**
 * @author imotov
 */
public class ZooKeeperDiscoveryModule extends AbstractModule {

    @Override protected void configure() {
        bind(ZooKeeperEnvironment.class).asEagerSingleton();
        bind(ZooKeeperFactory.class).asEagerSingleton();
        bind(Discovery.class).to(ZooKeeperDiscovery.class).asEagerSingleton();
        bind(ZooKeeperClient.class).to(ZooKeeperClientService.class).asEagerSingleton();
    }
}
