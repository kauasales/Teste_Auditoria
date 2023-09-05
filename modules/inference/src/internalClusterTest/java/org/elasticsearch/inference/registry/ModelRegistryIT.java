/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.inference.registry;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.inference.Model;
import org.elasticsearch.inference.TaskType;
import org.elasticsearch.inference.UnparsedModel;
import org.elasticsearch.inference.services.elser.ElserMlNodeService;
import org.elasticsearch.inference.services.elser.ElserMlNodeServiceTests;
import org.elasticsearch.test.ESSingleNodeTestCase;
import org.junit.Before;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

public class ModelRegistryIT extends ESSingleNodeTestCase {

    private ModelRegistry modelRegistry;

    @Before
    public void createComponents() throws Exception {
        modelRegistry = new ModelRegistry(client());
        // TODO wait for inference index template??
    }

    public void testStoreModel() throws Exception {
        String modelId = "test-store-model";
        Model model = buildModelConfig(modelId, ElserMlNodeService.NAME, TaskType.SPARSE_EMBEDDING);
        AtomicReference<Boolean> storeModelHolder = new AtomicReference<>();
        AtomicReference<Exception> exceptionHolder = new AtomicReference<>();

        blockingCall(listener -> modelRegistry.storeModel(model, listener), storeModelHolder, exceptionHolder);

        assertThat(storeModelHolder.get(), is(true));
        assertThat(exceptionHolder.get(), is(nullValue()));
    }

    public void testGetModel() throws Exception {
        String modelId = "test-get-model";
        Model model = buildModelConfig(modelId, ElserMlNodeService.NAME, TaskType.SPARSE_EMBEDDING);
        AtomicReference<Boolean> putModelHolder = new AtomicReference<>();
        AtomicReference<Exception> exceptionHolder = new AtomicReference<>();

        blockingCall(listener -> modelRegistry.storeModel(model, listener), putModelHolder, exceptionHolder);
        assertThat(putModelHolder.get(), is(true));

        // now get the model
        AtomicReference<ModelRegistry.ModelConfigMap> modelHolder = new AtomicReference<>();
        blockingCall(listener -> modelRegistry.getUnparsedModelMap(modelId, listener), modelHolder, exceptionHolder);
        assertThat(exceptionHolder.get(), is(nullValue()));
        assertThat(modelHolder.get(), not(nullValue()));

        UnparsedModel unparsedModel = UnparsedModel.unparsedModelFromMap(modelHolder.get().config());
        assertEquals(model.getService(), unparsedModel.service());
        Model roundTripModel = ElserMlNodeService.parseConfigLenient(unparsedModel.modelId(), unparsedModel.taskType(), unparsedModel.settings());
        assertEquals(model, roundTripModel);
    }

    public void testStoreModelFailsWhenModelExists() throws Exception {
        String modelId = "test-put-trained-model-config-exists";
        Model model = buildModelConfig(modelId, ElserMlNodeService.NAME, TaskType.SPARSE_EMBEDDING);
        AtomicReference<Boolean> putModelHolder = new AtomicReference<>();
        AtomicReference<Exception> exceptionHolder = new AtomicReference<>();

        blockingCall(listener -> modelRegistry.storeModel(model, listener), putModelHolder, exceptionHolder);
        assertThat(putModelHolder.get(), is(true));
        assertThat(exceptionHolder.get(), is(nullValue()));

        putModelHolder.set(false);
        // an model with the same id exists
        blockingCall(listener -> modelRegistry.storeModel(model, listener), putModelHolder, exceptionHolder);
        assertThat(putModelHolder.get(), is(false));
        assertThat(exceptionHolder.get(), not(nullValue()));
        assertThat(
            exceptionHolder.get().getMessage(),
            containsString("Inference model [test-put-trained-model-config-exists] already exists")
        );
    }

    public void testDeleteModel() throws Exception {
        // put models
        for (var id : new String[] { "model1", "model2", "model3" }) {
            Model model = buildModelConfig(id, ElserMlNodeService.NAME, TaskType.SPARSE_EMBEDDING);
            AtomicReference<Boolean> putModelHolder = new AtomicReference<>();
            AtomicReference<Exception> exceptionHolder = new AtomicReference<>();
            blockingCall(listener -> modelRegistry.storeModel(model, listener), putModelHolder, exceptionHolder);
            assertThat(putModelHolder.get(), is(true));
        }

        AtomicReference<Boolean> deleteResponseHolder = new AtomicReference<>();
        AtomicReference<Exception> exceptionHolder = new AtomicReference<>();
        blockingCall(listener -> modelRegistry.deleteModel("model1", listener), deleteResponseHolder, exceptionHolder);
        assertThat(exceptionHolder.get(), is(nullValue()));
        assertTrue(deleteResponseHolder.get());

        // get should fail
        deleteResponseHolder.set(false);
        AtomicReference<ModelRegistry.ModelConfigMap> modelHolder = new AtomicReference<>();
        blockingCall(listener -> modelRegistry.getUnparsedModelMap("model1", listener), modelHolder, exceptionHolder);

        assertThat(exceptionHolder.get(), not(nullValue()));
        assertFalse(deleteResponseHolder.get());
        assertThat(exceptionHolder.get().getMessage(), containsString("foo"));
    }

    private Model buildModelConfig(String modelId, String service, TaskType taskType) {
        return switch (service) {
            case ElserMlNodeService.NAME -> ElserMlNodeServiceTests.randomModelConfig(modelId, taskType);
            default -> throw new IllegalArgumentException("unknown service " + service);
        };
    }

    protected <T> void blockingCall(Consumer<ActionListener<T>> function, AtomicReference<T> response, AtomicReference<Exception> error)
        throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        ActionListener<T> listener = ActionListener.wrap(r -> {
            response.set(r);
            latch.countDown();
        }, e -> {
            error.set(e);
            latch.countDown();
        });

        function.accept(listener);
        latch.await();
    }
}
