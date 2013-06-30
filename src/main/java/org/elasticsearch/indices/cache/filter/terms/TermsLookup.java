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

package org.elasticsearch.indices.cache.filter.terms;

import org.apache.lucene.search.Filter;
import org.elasticsearch.client.Client;

import java.util.Collection;
import java.util.Iterator;

/**
 * Abstract {@link TermsLookup}.
 */
public abstract class TermsLookup {

    protected Client client;

    // TODO: Can this be injected?
    /**
     * Sets the client
     * @param client the {@link Client}
     */
    public void setClient(Client client) {
        this.client = client;
    }

    /**
     * Returns the lookup filter
     * @return the filter
     */
    public abstract Filter getFilter();

    /**
     * Used for cache key when not specified
     * @return the lookup string representation
     */
    public abstract String toString();

    /**
     * The size of the lookup in bytes to be used in
     * cache size calculations
     * @return the size of the lookup in bytes
     */
    public abstract long estimateSizeInBytes();
}
