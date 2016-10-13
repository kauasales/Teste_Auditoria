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

package org.elasticsearch.script;

import org.elasticsearch.script.Script.ScriptType;
import org.elasticsearch.search.lookup.SearchLookup;

import java.util.Map;

/**
 * CompiledScript holds all the parameters necessary to execute a previously compiled script.
 */
public class CompiledScript {

    private final ScriptType type;
    private final String id;
    private final ScriptEngineService engine;
    private final Object compiled;

    /**
     * Constructor for CompiledScript.
     * @param type The {@link ScriptType} of script to be executed.
     * @param id The id of the script to be executed.
     * @param engine The {@link ScriptEngineService} used to compile this script.
     * @param compiled The compiled script Object that is executable.
     */
    public CompiledScript(ScriptType type, String id, ScriptEngineService engine, Object compiled) {
        this.type = type;
        this.id = id;
        this.engine = engine;
        this.compiled = compiled;
    }

    /**
     * Method to get the type of language.
     * @return The {@link ScriptType} of script to be executed.
     */
    public ScriptType type() {
        return type;
    }

    /**
     * Method to get the name of the script.
     * @return The name of the script to be executed.
     */
    public String id() {
        return id;
    }

    /**
     * Method to get the language.
     * @return The language of the script to be executed.
     */
    public String lang() {
        return engine.getType();
    }

    /**
     * Method to get the {@link ScriptEngineService}.
     * @return The {@link ScriptEngineService} used to compiled this script.
     */
    ScriptEngineService engine() {
        return engine;
    }

    /**
     * Method to get the compiled script object.
     * @return The compiled script Object that is executable.
     */
    public Object compiled() {
        return compiled;
    }

    /**
     * @return A string composed of type, lang, and name to describe the CompiledScript.
     */
    @Override
    public String toString() {
        return type + " script [" + id + "] using lang [" + lang() + "]";
    }

    /**
     * Binds this {@link CompiledScript} to an {@link ExecutableScript}.
     * @param variables The variables to bind to the {@link ExecutableScript}.
     * @return An {@link ExecutableScript}.
     */
    public ExecutableScript bindExecutable(Map<String, Object> variables) {
        return engine.executable(this, variables);
    }

    /**
     * Binds this {@link CompiledScript} to an {@link SearchScript}.
     * @param variables The variables to bind to the {@link SearchScript}.
     * @return An {@link SearchScript}.
     */
    public SearchScript bindSearch(SearchLookup lookup, Map<String, Object> variables) {
        return engine.search(this, lookup, variables);
    }
}
