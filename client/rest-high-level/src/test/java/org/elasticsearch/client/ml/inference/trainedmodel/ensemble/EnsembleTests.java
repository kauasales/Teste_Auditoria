/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.elasticsearch.client.ml.inference.trainedmodel.ensemble;

import org.elasticsearch.client.ml.inference.MlInferenceNamedXContentProvider;
import org.elasticsearch.client.ml.inference.trainedmodel.TargetType;
import org.elasticsearch.client.ml.inference.trainedmodel.TrainedModel;
import org.elasticsearch.client.ml.inference.trainedmodel.tree.TreeTests;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.search.SearchModule;
import org.elasticsearch.test.AbstractXContentTestCase;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class EnsembleTests extends AbstractXContentTestCase<Ensemble> {

    @Override
    protected boolean supportsUnknownFields() {
        return true;
    }

    @Override
    protected Predicate<String> getRandomFieldsExcludeFilter() {
        return field -> !field.isEmpty();
    }

    @Override
    protected Ensemble doParseInstance(XContentParser parser) throws IOException {
        return Ensemble.fromXContent(parser);
    }

    public static Ensemble createRandom() {
        return createRandom(randomFrom(TargetType.values()));
    }

    public static Ensemble createRandom(TargetType targetType) {
        int numberOfFeatures = randomIntBetween(1, 10);
        List<String> featureNames = Stream.generate(() -> randomAlphaOfLength(10))
            .limit(numberOfFeatures)
            .collect(Collectors.toList());
        int numberOfModels = randomIntBetween(1, 10);
        List<TrainedModel> models = Stream.generate(() -> TreeTests.buildRandomTree(featureNames, 6, targetType))
            .limit(numberOfFeatures)
            .collect(Collectors.toList());
        OutputAggregator outputAggregator = null;
        if (randomBoolean()) {
            List<Double> weights = Stream.generate(ESTestCase::randomDouble).limit(numberOfModels).collect(Collectors.toList());
            outputAggregator = randomFrom(new WeightedMode(weights), new WeightedSum(weights), new LogisticRegression(weights));
        }
        List<String> categoryLabels = null;
        if (randomBoolean()) {
            categoryLabels = Arrays.asList(generateRandomStringArray(randomIntBetween(1, 10), randomIntBetween(1, 10), false, false));
        }
        return new Ensemble(featureNames,
            models,
            outputAggregator,
            targetType,
            categoryLabels);
    }

    @Override
    protected Ensemble createTestInstance() {
        return createRandom();
    }

    @Override
    protected NamedXContentRegistry xContentRegistry() {
        List<NamedXContentRegistry.Entry> namedXContent = new ArrayList<>();
        namedXContent.addAll(new MlInferenceNamedXContentProvider().getNamedXContentParsers());
        namedXContent.addAll(new SearchModule(Settings.EMPTY, Collections.emptyList()).getNamedXContents());
        return new NamedXContentRegistry(namedXContent);
    }

}
