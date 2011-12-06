/*
 * Licensed to ElasticSearch and Shay Banon under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. ElasticSearch licenses this
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

package org.elasticsearch.index.translog.fs;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 */
public class RafReference {

    private final File file;

    private final RandomAccessFile raf;

    private final FileChannel channel;

    private final AtomicInteger refCount = new AtomicInteger();

    public RafReference(File file) throws FileNotFoundException {
        this.file = file;
        this.raf = new RandomAccessFile(file, "rw");
        this.channel = raf.getChannel();
        this.refCount.incrementAndGet();
    }

    public File file() {
        return this.file;
    }

    public FileChannel channel() {
        return this.channel;
    }

    public RandomAccessFile raf() {
        return this.raf;
    }

    /**
     * Increases the ref count, and returns <tt>true</tt> if it managed to
     * actually increment it.
     */
    public boolean increaseRefCount() {
        return refCount.incrementAndGet() > 1;
    }

    public void decreaseRefCount(boolean delete) {
        if (refCount.decrementAndGet() <= 0) {
            try {
                raf.close();
                if (delete) {
                    file.delete();
                }
            } catch (IOException e) {
                // ignore
            }
        }
    }
}
