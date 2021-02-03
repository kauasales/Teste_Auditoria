/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.transform.action;

import org.elasticsearch.Version;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.NamedWriteableAwareStreamInput;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.search.SearchModule;
import org.elasticsearch.test.AbstractSerializingTestCase;
import org.elasticsearch.xpack.core.transform.TransformField;
import org.elasticsearch.xpack.core.transform.TransformNamedXContentProvider;
import org.elasticsearch.xpack.core.transform.transforms.SyncConfig;
import org.elasticsearch.xpack.core.transform.transforms.TimeSyncConfig;
import org.junit.Before;

import java.io.IOException;
import java.util.List;

import static java.util.Collections.emptyList;

public abstract class AbstractSerializingTransformTestCase<T extends ToXContent & Writeable> extends AbstractSerializingTestCase<T> {

    private NamedWriteableRegistry namedWriteableRegistry;
    private NamedXContentRegistry namedXContentRegistry;

    @Before
    public void registerNamedObjects() {
        SearchModule searchModule = new SearchModule(Settings.EMPTY, false, emptyList());

        List<NamedWriteableRegistry.Entry> namedWriteables = searchModule.getNamedWriteables();
        namedWriteables.add(
            new NamedWriteableRegistry.Entry(SyncConfig.class, TransformField.TIME_BASED_SYNC.getPreferredName(), TimeSyncConfig::new)
        );

        List<NamedXContentRegistry.Entry> namedXContents = searchModule.getNamedXContents();
        namedXContents.addAll(new TransformNamedXContentProvider().getNamedXContentParsers());

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

    protected <X extends Writeable, Y extends Writeable> Y writeAndReadBWCObject(
        X original,
        NamedWriteableRegistry namedWriteableRegistry,
        Writeable.Writer<X> writer,
        Writeable.Reader<Y> reader,
        Version version
    ) throws IOException {
        try (BytesStreamOutput output = new BytesStreamOutput()) {
            output.setVersion(version);
            original.writeTo(output);

            try (StreamInput in = new NamedWriteableAwareStreamInput(output.bytes().streamInput(), getNamedWriteableRegistry())) {
                in.setVersion(version);
                return reader.read(in);
            }
        }
    }

}
