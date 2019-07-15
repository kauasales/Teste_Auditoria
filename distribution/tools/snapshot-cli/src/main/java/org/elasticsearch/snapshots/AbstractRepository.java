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
package org.elasticsearch.snapshots;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionRunnable;
import org.elasticsearch.action.support.GroupedActionListener;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.repositories.IndexId;
import org.elasticsearch.repositories.RepositoryData;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public abstract class AbstractRepository implements Repository {
    private static final long DEFAULT_SAFETY_GAP_MILLIS = 3600 * 1000;
    private static final int DEFAULT_PARALLELISM = 100;

    protected final Terminal terminal;
    private final long safetyGapMillis;
    private final int parallelism;

    protected AbstractRepository(Terminal terminal, Long safetyGapMillis, Integer parallelism) {
        this.terminal = terminal;
        this.safetyGapMillis = safetyGapMillis == null ? DEFAULT_SAFETY_GAP_MILLIS : safetyGapMillis;
        this.parallelism = parallelism == null ? DEFAULT_PARALLELISM : parallelism;
    }

    private void describeCollection(String start, Collection<?> elements) {
        terminal.println(Terminal.Verbosity.VERBOSE,
                start + " has " + elements.size() + " elements: " + elements);
    }

    @Override
    public void cleanup() throws IOException {
        terminal.println(Terminal.Verbosity.VERBOSE, "Obtaining latest index file generation and creation timestamp");
        Tuple<Long, Date> latestIndexIdAndTimestamp = getLatestIndexIdAndTimestamp();
        if (latestIndexIdAndTimestamp.v1() == -1) {
            terminal.println(Terminal.Verbosity.NORMAL, "No index-N files found. Repository is empty or corrupted? Exiting");
            return;
        }
        long latestIndexId = latestIndexIdAndTimestamp.v1();
        terminal.println(Terminal.Verbosity.VERBOSE, "Latest index file generation is " + latestIndexId);
        Date indexNTimestamp = latestIndexIdAndTimestamp.v2();
        Date shiftedIndexNTimestamp = new Date(indexNTimestamp.getTime() - safetyGapMillis);
        terminal.println(Terminal.Verbosity.VERBOSE, "Latest index file creation timestamp is " + indexNTimestamp);
        terminal.println(Terminal.Verbosity.VERBOSE, "Shifted by safety gap creation timestamp is " + shiftedIndexNTimestamp);

        terminal.println(Terminal.Verbosity.VERBOSE, "Reading latest index file");
        final RepositoryData repositoryData = getRepositoryData(latestIndexId);
        if (repositoryData.getIncompatibleSnapshotIds().isEmpty() == false) {
            throw new ElasticsearchException(
                "Found incompatible snapshots which prevent a safe cleanup execution " + repositoryData.getIncompatibleSnapshotIds());
        }
        if (repositoryData.getIndices().isEmpty()) {
            throw new ElasticsearchException(
                "The repository data contains no references to any indices. Maybe it is from before version 5.x?");
        }
        Set<String> referencedIndexIds = repositoryData.getIndices().values().stream().map(IndexId::getId).collect(Collectors.toSet());

        describeCollection("Set of indices referenced by index file", referencedIndexIds);

        terminal.println(Terminal.Verbosity.VERBOSE, "Listing indices/ directory");
        Set<String> allIndexIds = getAllIndexDirectoryNames();
        describeCollection("Set of indices inside indices/ directory", allIndexIds);

        Set<String> deletionCandidates = new TreeSet<>(Sets.difference(allIndexIds, referencedIndexIds));
        describeCollection("Set of deletion candidates", deletionCandidates);
        if (deletionCandidates.isEmpty()) {
            terminal.println(Terminal.Verbosity.NORMAL, "Set of deletion candidates is empty. Exiting");
            return;
        }

        ExecutorService executor = EsExecutors.newScaling("snapshot_cleanup", 0, parallelism, 10L, TimeUnit.SECONDS,
            EsExecutors.daemonThreadFactory("snapshot_cleanup_tool"), new ThreadContext(Settings.EMPTY));
        try {
            PlainActionFuture<Collection<String>> orphanedIndicesFuture = new PlainActionFuture<>();
            GroupedActionListener<String> groupedOrphanedIndicesListener = new GroupedActionListener<>(orphanedIndicesFuture,
                    deletionCandidates.size());
            for (String candidate : deletionCandidates) {
                executor.submit(new ActionRunnable<>(groupedOrphanedIndicesListener) {
                    @Override
                    protected void doRun() {
                        if (isOrphaned(candidate, shiftedIndexNTimestamp)) {
                            groupedOrphanedIndicesListener.onResponse(candidate);
                        } else {
                            groupedOrphanedIndicesListener.onResponse(null);
                        }
                    }
                });
            }
            Set<String> orphanedIndexIds =
                    new TreeSet<>(orphanedIndicesFuture.actionGet().stream().filter(Objects::nonNull).collect(Collectors.toSet()));
            describeCollection("Set of orphaned indices", orphanedIndexIds);
            if (orphanedIndexIds.isEmpty()) {
                terminal.println(Terminal.Verbosity.NORMAL, "Set of orphaned indices is empty. Exiting");
                return;
            }

            confirm(terminal, orphanedIndexIds.size() + " indices have been found. Do you want to remove orphaned indices files? " +
                    "This action is NOT REVERSIBLE");

            terminal.println(Terminal.Verbosity.NORMAL, "Removing " + orphanedIndexIds.size() + " orphaned indices");
            PlainActionFuture<Collection<Void>> removalFuture = new PlainActionFuture<>();
            final List<Tuple<Integer, Long>> results = Collections.synchronizedList(new ArrayList<>());
            GroupedActionListener<Void> groupedRemovalListener =
                    new GroupedActionListener<>(removalFuture, orphanedIndexIds.size());
            for (final String indexId : orphanedIndexIds) {
                executor.submit(new ActionRunnable<>(groupedRemovalListener) {
                    @Override
                    protected void doRun() {
                        terminal.println(Terminal.Verbosity.NORMAL, "Removing orphaned index " + indexId);
                        Tuple<Integer, Long> countSize = deleteIndex(indexId);
                        terminal.println("Index directory " + indexId + ", files removed " + countSize.v1() +
                                ", bytes freed " + countSize.v2());
                        results.add(countSize);
                        groupedRemovalListener.onResponse(null);
                    }
                });
            }
            Exception ex = null;
            try {
                removalFuture.actionGet();
            } catch (Exception e) {
                ex = e;
            }
            int totalFilesRemoved = results.stream().mapToInt(Tuple::v1).sum();
            long totalSpaceFreed = results.stream().mapToLong(Tuple::v2).sum();
            terminal.println(Terminal.Verbosity.NORMAL, "Total files removed: " + totalFilesRemoved);
            terminal.println(Terminal.Verbosity.NORMAL, "Total bytes freed: " + totalSpaceFreed);
            terminal.println(Terminal.Verbosity.NORMAL,
                "Finished removing " + results.size() + "/" + orphanedIndexIds.size() + " orphaned indices");
            if (ex != null) {
                throw new ElasticsearchException(ex);
            }
        } finally {
            executor.shutdown();
            try {
                if (executor.awaitTermination(30, TimeUnit.SECONDS) == false) {
                    terminal.println(Terminal.Verbosity.NORMAL, "Unexpectedly there are still tasks running on the executor");
                }
            } catch (InterruptedException e) {
                throw new ElasticsearchException(e);
            }
        }
    }

    private boolean isOrphaned(String candidate, Date shiftedIndexNTimestamp) {
        terminal.println(Terminal.Verbosity.VERBOSE, "Reading index " + candidate + " last modification timestamp");
        Date indexTimestamp = getIndexTimestamp(candidate);
        if (indexTimestamp != null) {
            if (indexTimestamp.before(shiftedIndexNTimestamp)) {
                terminal.println(Terminal.Verbosity.VERBOSE,
                        "Index " + candidate + " is orphaned because its modification timestamp " + indexTimestamp +
                                " is less than index-N shifted timestamp " + shiftedIndexNTimestamp);
                return true;
            } else {
                terminal.println(Terminal.Verbosity.VERBOSE,
                        "Index  " + candidate + " might not be orphaned because its modification timestamp "
                                + indexTimestamp +
                                " is gte than index-N shifted timestamp " + shiftedIndexNTimestamp);
            }
        }
        return false;
    }

    private void confirm(Terminal terminal, String msg) {
        terminal.println(Terminal.Verbosity.NORMAL, msg);
        String text = terminal.readText("Confirm [y/N] ");
        if (text.equalsIgnoreCase("y") == false) {
            throw new ElasticsearchException("Aborted by user");
        }
    }
}
