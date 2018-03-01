/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
package org.elasticsearch.index.engine;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.IndexSettingsModule;


public class EngineConfigTests extends ESTestCase {


    private EngineConfig createEngineConfigWithSettings(IndexSettings indexSettings) {
        return new EngineConfig(EngineConfig.OpenMode.OPEN_INDEX_AND_TRANSLOG, null, null, null,
            indexSettings, null, null, null, null,
            null, null, null, null, null,
            true, null, null, null, null, null,
            null, null, null);
    }

    public void testOptimizeAutoGeneratedIdsSettingDeprecation() throws Exception {
        Version version = randomFrom(Version.V_6_0_0_rc1, Version.V_6_0_0, Version.V_6_2_0, Version.V_6_3_0);
        boolean optimizeAutoGeneratedIds = randomBoolean();
        Settings.Builder builder = Settings.builder()
            .put(IndexMetaData.SETTING_VERSION_CREATED, version)
            .put(EngineConfig.INDEX_OPTIMIZE_AUTO_GENERATED_IDS.getKey(), optimizeAutoGeneratedIds);
        IndexSettings indexSettings = IndexSettingsModule.newIndexSettings("index1", builder.build());

        EngineConfig config = createEngineConfigWithSettings(indexSettings);
        assertWarnings("Setting [" + EngineConfig.INDEX_OPTIMIZE_AUTO_GENERATED_IDS.getKey()
            + "] has been deprecated in favor of the auto-ID optimization");
        assertEquals(optimizeAutoGeneratedIds, config.isAutoGeneratedIDsOptimizationEnabled());

        version = randomFrom(Version.V_5_0_0, Version.V_5_0_0_alpha1, Version.V_5_6_9);
        optimizeAutoGeneratedIds = randomBoolean();
        builder = Settings.builder()
            .put(IndexMetaData.SETTING_VERSION_CREATED, version)
            .put(EngineConfig.INDEX_OPTIMIZE_AUTO_GENERATED_IDS.getKey(), optimizeAutoGeneratedIds);
        indexSettings = IndexSettingsModule.newIndexSettings("index2", builder.build());
        config = createEngineConfigWithSettings(indexSettings);
        assertEquals(optimizeAutoGeneratedIds, config.isAutoGeneratedIDsOptimizationEnabled());

        version = randomFrom(Version.V_6_0_0_rc1, Version.V_6_0_0, Version.V_6_2_0, Version.V_6_3_0);
        builder = Settings.builder().put(IndexMetaData.SETTING_VERSION_CREATED, version);
        indexSettings = IndexSettingsModule.newIndexSettings("index3", builder.build());
        config = createEngineConfigWithSettings(indexSettings);
        assertTrue(config.isAutoGeneratedIDsOptimizationEnabled());
    }

}
