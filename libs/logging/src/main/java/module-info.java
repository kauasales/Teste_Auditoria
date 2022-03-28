/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

module org.elasticsearch.logging {
    requires org.elasticsearch.cli;
    requires org.elasticsearch.core;
    requires org.elasticsearch.xcontent;
    requires log4j2.ecs.layout;
    requires ecs.logging.core;
    requires org.apache.logging.log4j;
    requires org.apache.logging.log4j.core;
    requires org.hamcrest;

    exports org.elasticsearch.logging;
    exports org.elasticsearch.logging.internal.spi to org.elasticsearch.server;

    // exports org.elasticsearch.logging.internal2;
    // opens org.elasticsearch.logging.internal2;

    opens org.elasticsearch.logging.internal;

    exports org.elasticsearch.logging.internal;

    exports org.elasticsearch.logging.api.core;

    opens org.elasticsearch.logging.api.core to org.apache.logging.log4j.core;

    exports org.elasticsearch.logging.internal.testing;

    opens org.elasticsearch.logging.internal.testing to org.apache.logging.log4j.core;

    uses org.elasticsearch.logging.internal.spi.ServerSupport;
}
