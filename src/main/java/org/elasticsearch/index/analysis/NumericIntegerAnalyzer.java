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

package org.elasticsearch.index.analysis;

import gnu.trove.map.hash.TIntObjectHashMap;
import org.apache.lucene.util.NumericUtils;

import java.io.IOException;
import java.io.Reader;

/**
 *
 */
public class NumericIntegerAnalyzer extends NumericAnalyzer<NumericIntegerTokenizer> {

    private final static TIntObjectHashMap<NamedAnalyzer> builtIn;

    static {
        builtIn = new TIntObjectHashMap<NamedAnalyzer>();
        builtIn.put(Integer.MAX_VALUE, new NamedAnalyzer("_int/max", AnalyzerScope.GLOBAL, new NumericIntegerAnalyzer(Integer.MAX_VALUE)));
        for (int i = 0; i <= 64; i += 4) {
            builtIn.put(i, new NamedAnalyzer("_int/" + i, AnalyzerScope.GLOBAL, new NumericIntegerAnalyzer(i)));
        }
    }

    public static NamedAnalyzer buildNamedAnalyzer(int precisionStep) {
        NamedAnalyzer namedAnalyzer = builtIn.get(precisionStep);
        if (namedAnalyzer == null) {
            namedAnalyzer = new NamedAnalyzer("_int/" + precisionStep, AnalyzerScope.INDEX, new NumericIntegerAnalyzer(precisionStep));
        }
        return namedAnalyzer;
    }

    private final int precisionStep;

    public NumericIntegerAnalyzer() {
        this(NumericUtils.PRECISION_STEP_DEFAULT);
    }

    public NumericIntegerAnalyzer(int precisionStep) {
        this.precisionStep = precisionStep;
    }

    @Override
    protected NumericIntegerTokenizer createNumericTokenizer(Reader reader, char[] buffer) throws IOException {
        return new NumericIntegerTokenizer(reader, precisionStep, buffer);
    }
}
