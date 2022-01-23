/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package org.elasticsearch.persistent.decider;

import java.util.Locale;
import java.util.Objects;

/**
 * {@link AssignmentDecision} represents the decision made during the process of
 * assigning a persistent task to a node of the cluster.
 *
 * @see EnableAssignmentDecider
 */
public record AssignmentDecision(org.elasticsearch.persistent.decider.AssignmentDecision.Type type, String reason) {

    public static final AssignmentDecision YES = new AssignmentDecision(Type.YES, "");

    public AssignmentDecision {
        Objects.requireNonNull(type);
        Objects.requireNonNull(reason);
    }

    @Override
    public String toString() {
        return "assignment decision [type=" + type + ", reason=" + reason + "]";
    }

    public enum Type {
        NO(0),
        YES(1);

        private final int id;

        Type(int id) {
            this.id = id;
        }

        public int getId() {
            return id;
        }

        public static Type resolve(final String s) {
            return Type.valueOf(s.toUpperCase(Locale.ROOT));
        }
    }
}
