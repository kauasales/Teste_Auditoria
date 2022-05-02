/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.server.cli;

import org.elasticsearch.cli.Terminal;
import org.elasticsearch.common.settings.SecureString;

import java.io.Closeable;
import java.io.OutputStream;

class KeystorePasswordTerminal extends Terminal implements Closeable {

    private final Terminal delegate;
    private final SecureString password;

    protected KeystorePasswordTerminal(Terminal delegate, SecureString password) {
        super(delegate.getReader(), delegate.getWriter(), delegate.getErrorWriter());
        this.delegate = delegate;
        this.password = password;
    }

    @Override
    public char[] readSecret(String prompt) {
        return password.getChars();
    }

    @Override
    public OutputStream getOutputStream() {
        return delegate.getOutputStream();
    }

    @Override
    public void close() {
        password.close();
    }
}
