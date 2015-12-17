package org.elasticsearch.plugin.reindex;

import static org.apache.lucene.util.TestUtil.randomSimpleString;
import static org.hamcrest.Matchers.either;
import static org.hamcrest.Matchers.equalTo;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.index.engine.VersionConflictEngineException;

/**
 * Mutates a document while update-by-query-ing it and asserts that the mutation
 * always sticks. Update-by-query should never revert.
 */
public class UpdateByQueryWhileModifyingTest extends UpdateByQueryTestCase {
    private static final int MAX_MUTATIONS = 50;
    private static final int MAX_ATTEMPTS = 10;

    public void testUpdateWhileReindexing() throws Exception {
        AtomicReference<String> value = new AtomicReference<>(randomSimpleString(random()));
        indexRandom(true, client().prepareIndex("test", "test", "test").setSource("test", value.get()));

        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean keepUpdating = new AtomicBoolean(true);
        Thread updater = new Thread(new Runnable() {
            @Override
            public void run() {
                while (keepUpdating.get()) {
                    try {
                        assertThat(request().source("test").get(),
                                responseMatcher().updated(either(equalTo(0L)).or(equalTo(1L)))
                                        .versionConflicts(either(equalTo(0L)).or(equalTo(1L))));
                        client().admin().indices().prepareRefresh("test").get();
                    } catch (Throwable t) {
                        failure.set(t);
                    }
                }
            }
        });
        updater.start();

        try {
            for (int i = 0; i < MAX_MUTATIONS; i++) {
                GetResponse get = client().prepareGet("test", "test", "test").get();
                assertEquals(value.get(), get.getSource().get("test"));
                value.set(randomSimpleString(random()));
                IndexRequestBuilder index = client().prepareIndex("test", "test", "test").setSource("test", value.get())
                        .setRefresh(true);
                /*
                 * Reindex increments the version number so concurrent indexes
                 * might get version conflict exceptions so we just blindly
                 * retry.
                 */
                int attempts = 0;
                while (true) {
                    attempts++;
                    try {
                        index.setVersion(get.getVersion()).get();
                        break;
                    } catch (VersionConflictEngineException e) {
                        if (attempts >= MAX_ATTEMPTS) {
                            throw new RuntimeException("Failed to index after [" + MAX_ATTEMPTS + "] attempts. Too many version conflicts!");
                        }
                        logger.info(
                                "Caught expected version conflict trying to perform mutation number {} with version {}. Retrying.",
                                i, get.getVersion());
                        get = client().prepareGet("test", "test", "test").get();
                        continue;
                    }
                }
            }
        } finally {
            keepUpdating.set(false);
            updater.join(TimeUnit.SECONDS.toMillis(10));
            if (failure.get() != null) {
                throw new RuntimeException(failure.get());
            }
        }
    }

}
