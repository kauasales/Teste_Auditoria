/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.dataframe.action;

import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.search.SearchModule;
import org.elasticsearch.test.AbstractWireSerializingTestCase;
import org.junit.Before;

import java.util.List;

import static java.util.Collections.emptyList;

public abstract class AbstractWireSerializingDataFrameTestCase<T extends Writeable> extends AbstractWireSerializingTestCase<T> {
    /**
     * Test case that ensures aggregation named objects are registered
     */
    private NamedWriteableRegistry namedWriteableRegistry;
    private NamedXContentRegistry namedXContentRegistry;

    @Before
    public void registerNamedObjects() {
        SearchModule searchModule = new SearchModule(Settings.EMPTY, false, emptyList());

        List<NamedWriteableRegistry.Entry> namedWriteables = searchModule.getNamedWriteables();
        List<NamedXContentRegistry.Entry> namedXContents = searchModule.getNamedXContents();

        namedWriteableRegistry = new NamedWriteableRegistry(namedWriteables);
        namedXContentRegistry = new NamedXContentRegistry(namedXContents);
    }

    @Override
    protected NamedWriteableRegistry getNamedWriteableRegistry() {
        return namedWriteableRegistry;
    }

    @Override
    protected NamedXContentRegistry xContentRegistry() {
        return namedXContentRegistry;
    }
}
