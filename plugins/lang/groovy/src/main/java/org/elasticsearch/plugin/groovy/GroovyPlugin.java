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

package org.elasticsearch.plugin.groovy;

import org.elasticsearch.common.inject.Module;
import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.script.ScriptModule;
import org.elasticsearch.script.groovy.GroovyScriptEngineService;

/**
 * @author kimchy (shay.banon)
 */
public class GroovyPlugin extends AbstractPlugin {

    @Override public String name() {
        return "lang-groovy";
    }

    @Override public String description() {
        return "Groovy plugin allowing to add groovy scripting support";
    }

    @Override public void processModule(Module module) {
        if (module instanceof ScriptModule) {
            ((ScriptModule) module).addScriptEngine(GroovyScriptEngineService.class);
        }
    }
}
