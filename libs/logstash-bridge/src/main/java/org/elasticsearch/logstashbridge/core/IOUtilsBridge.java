/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package org.elasticsearch.logstashbridge.core;

import org.elasticsearch.core.IOUtils;

import java.io.Closeable;

public class IOUtilsBridge {
    public static void closeWhileHandlingException(final Iterable<? extends Closeable> objects) {
        IOUtils.closeWhileHandlingException(objects);
    }

    public static void closeWhileHandlingException(final Closeable closeable) {
        IOUtils.closeWhileHandlingException(closeable);
    }
}
