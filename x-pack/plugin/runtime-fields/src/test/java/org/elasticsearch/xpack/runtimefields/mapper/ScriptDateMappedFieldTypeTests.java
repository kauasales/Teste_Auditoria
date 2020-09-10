/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.runtimefields.mapper;

import org.apache.lucene.document.StoredField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.RandomIndexWriter;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.search.Collector;
import org.apache.lucene.search.Explanation;
import org.apache.lucene.search.FieldDoc;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.LeafCollector;
import org.apache.lucene.search.MatchAllDocsQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.Scorable;
import org.apache.lucene.search.ScoreMode;
import org.apache.lucene.search.Sort;
import org.apache.lucene.search.SortField;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.TopFieldDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.Version;
import org.elasticsearch.common.lucene.search.function.ScriptScoreQuery;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.time.DateFormatter;
import org.elasticsearch.index.fielddata.ScriptDocValues;
import org.elasticsearch.index.mapper.DateFieldMapper;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.plugins.ScriptPlugin;
import org.elasticsearch.script.ScoreScript;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptContext;
import org.elasticsearch.script.ScriptEngine;
import org.elasticsearch.script.ScriptModule;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.script.ScriptType;
import org.elasticsearch.search.MultiValueMode;
import org.elasticsearch.xpack.runtimefields.DateScriptFieldScript;
import org.elasticsearch.xpack.runtimefields.RuntimeFields;
import org.elasticsearch.xpack.runtimefields.fielddata.ScriptDateFieldData;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.arrayWithSize;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

public class ScriptDateMappedFieldTypeTests extends AbstractNonTextScriptMappedFieldTypeTestCase {
    public void testFormat() throws IOException {
        assertThat(simpleMappedFieldType().docValueFormat("date", null).format(1595432181354L), equalTo("2020-07-22"));
        assertThat(
            simpleMappedFieldType().docValueFormat("strict_date_optional_time", null).format(1595432181354L),
            equalTo("2020-07-22T15:36:21.354Z")
        );
        assertThat(
            simpleMappedFieldType().docValueFormat("strict_date_optional_time", ZoneId.of("America/New_York")).format(1595432181354L),
            equalTo("2020-07-22T11:36:21.354-04:00")
        );
        assertThat(
            simpleMappedFieldType().docValueFormat(null, ZoneId.of("America/New_York")).format(1595432181354L),
            equalTo("2020-07-22T11:36:21.354-04:00")
        );
        assertThat(coolFormattedFieldType().docValueFormat(null, null).format(1595432181354L), equalTo("2020-07-22(-■_■)15:36:21.354Z"));
    }

    public void testFormatDuel() throws IOException {
        DateFormatter formatter = DateFormatter.forPattern(randomDateFormatterPattern()).withLocale(randomLocale(random()));
        ScriptDateMappedFieldType scripted = build(new Script(ScriptType.INLINE, "test", "read_timestamp", Map.of()), formatter);
        DateFieldMapper.DateFieldType indexed = new DateFieldMapper.DateFieldType("test", formatter);
        for (int i = 0; i < 100; i++) {
            long date = randomLongBetween(0, 3000000000000L); // Maxes out in the year 2065
            assertThat(indexed.docValueFormat(null, null).format(date), equalTo(scripted.docValueFormat(null, null).format(date)));
            String format = randomDateFormatterPattern();
            assertThat(indexed.docValueFormat(format, null).format(date), equalTo(scripted.docValueFormat(format, null).format(date)));
            ZoneId zone = randomZone();
            assertThat(indexed.docValueFormat(null, zone).format(date), equalTo(scripted.docValueFormat(null, zone).format(date)));
            assertThat(indexed.docValueFormat(format, zone).format(date), equalTo(scripted.docValueFormat(format, zone).format(date)));
        }
    }

    @Override
    public void testDocValues() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181354]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181356, 1595432181351]}"))));
            List<Long> results = new ArrayList<>();
            try (DirectoryReader reader = iw.getReader()) {
                IndexSearcher searcher = newSearcher(reader);
                ScriptDateMappedFieldType ft = build("add_days", Map.of("days", 1));
                ScriptDateFieldData ifd = ft.fielddataBuilder("test", mockContext()::lookup).build(null, null, null);
                searcher.search(new MatchAllDocsQuery(), new Collector() {
                    @Override
                    public ScoreMode scoreMode() {
                        return ScoreMode.COMPLETE_NO_SCORES;
                    }

                    @Override
                    public LeafCollector getLeafCollector(LeafReaderContext context) throws IOException {
                        SortedNumericDocValues dv = ifd.load(context).getLongValues();
                        return new LeafCollector() {
                            @Override
                            public void setScorer(Scorable scorer) throws IOException {}

                            @Override
                            public void collect(int doc) throws IOException {
                                if (dv.advanceExact(doc)) {
                                    for (int i = 0; i < dv.docValueCount(); i++) {
                                        results.add(dv.nextValue());
                                    }
                                }
                            }
                        };
                    }
                });
                assertThat(results, equalTo(List.of(1595518581354L, 1595518581351L, 1595518581356L)));
            }
        }
    }

    @Override
    public void testSort() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181354]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181351]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181356]}"))));
            try (DirectoryReader reader = iw.getReader()) {
                IndexSearcher searcher = newSearcher(reader);
                ScriptDateFieldData ifd = simpleMappedFieldType().fielddataBuilder("test", mockContext()::lookup).build(null, null, null);
                SortField sf = ifd.sortField(null, MultiValueMode.MIN, null, false);
                TopFieldDocs docs = searcher.search(new MatchAllDocsQuery(), 3, new Sort(sf));
                assertThat(readSource(reader, docs.scoreDocs[0].doc), equalTo("{\"timestamp\": [1595432181351]}"));
                assertThat(readSource(reader, docs.scoreDocs[1].doc), equalTo("{\"timestamp\": [1595432181354]}"));
                assertThat(readSource(reader, docs.scoreDocs[2].doc), equalTo("{\"timestamp\": [1595432181356]}"));
                assertThat((Long) (((FieldDoc) docs.scoreDocs[0]).fields[0]), equalTo(1595432181351L));
                assertThat((Long) (((FieldDoc) docs.scoreDocs[1]).fields[0]), equalTo(1595432181354L));
                assertThat((Long) (((FieldDoc) docs.scoreDocs[2]).fields[0]), equalTo(1595432181356L));
            }
        }
    }

    @Override
    public void testUsedInScript() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181354]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181351]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181356]}"))));
            try (DirectoryReader reader = iw.getReader()) {
                IndexSearcher searcher = newSearcher(reader);
                QueryShardContext qsc = mockContext(true, simpleMappedFieldType());
                assertThat(searcher.count(new ScriptScoreQuery(new MatchAllDocsQuery(), new Script("test"), new ScoreScript.LeafFactory() {
                    @Override
                    public boolean needs_score() {
                        return false;
                    }

                    @Override
                    public ScoreScript newInstance(LeafReaderContext ctx) throws IOException {
                        return new ScoreScript(Map.of(), qsc.lookup(), ctx) {
                            @Override
                            public double execute(ExplanationHolder explanation) {
                                ScriptDocValues.Dates dates = (ScriptDocValues.Dates) getDoc().get("test");
                                return dates.get(0).toInstant().toEpochMilli() % 1000;
                            }
                        };
                    }
                }, 354.5f, "test", 0, Version.CURRENT)), equalTo(1));
            }
        }
    }

    public void testDistanceFeatureQuery() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocuments(
                List.of(
                    List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181354]}"))),
                    List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181351]}"))),
                    List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181356, 1]}"))),
                    List.of(new StoredField("_source", new BytesRef("{\"timestamp\": []}")))
                )
            );
            try (DirectoryReader reader = iw.getReader()) {
                IndexSearcher searcher = newSearcher(reader);
                Query query = simpleMappedFieldType().distanceFeatureQuery(1595432181354L, "1ms", 1, mockContext());
                TopDocs docs = searcher.search(query, 4);
                assertThat(docs.scoreDocs, arrayWithSize(3));
                assertThat(readSource(reader, docs.scoreDocs[0].doc), equalTo("{\"timestamp\": [1595432181354]}"));
                assertThat(docs.scoreDocs[0].score, equalTo(1.0F));
                assertThat(readSource(reader, docs.scoreDocs[1].doc), equalTo("{\"timestamp\": [1595432181356, 1]}"));
                assertThat((double) docs.scoreDocs[1].score, closeTo(.333, .001));
                assertThat(readSource(reader, docs.scoreDocs[2].doc), equalTo("{\"timestamp\": [1595432181351]}"));
                assertThat((double) docs.scoreDocs[2].score, closeTo(.250, .001));
                Explanation explanation = query.createWeight(searcher, ScoreMode.TOP_SCORES, 1.0F)
                    .explain(reader.leaves().get(0), docs.scoreDocs[0].doc);
                assertThat(explanation.toString(), containsString("1.0 = Distance score, computed as weight * pivot / (pivot"));
                assertThat(explanation.toString(), containsString("1.0 = weight"));
                assertThat(explanation.toString(), containsString("1 = pivot"));
                assertThat(explanation.toString(), containsString("1595432181354 = origin"));
                assertThat(explanation.toString(), containsString("1595432181354 = current value"));
            }
        }
    }

    public void testDistanceFeatureQueryIsExpensive() throws IOException {
        checkExpensiveQuery((ft, ctx) -> ft.distanceFeatureQuery(randomLong(), randomAlphaOfLength(5), randomFloat(), ctx));
    }

    @Override
    public void testExistsQuery() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181356]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": []}"))));
            try (DirectoryReader reader = iw.getReader()) {
                IndexSearcher searcher = newSearcher(reader);
                assertThat(searcher.count(simpleMappedFieldType().existsQuery(mockContext())), equalTo(1));
            }
        }
    }

    @Override
    public void testExistsQueryIsExpensive() throws IOException {
        checkExpensiveQuery(ScriptDateMappedFieldType::existsQuery);
    }

    @Override
    public void testRangeQuery() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181354]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181351]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181356]}"))));
            try (DirectoryReader reader = iw.getReader()) {
                IndexSearcher searcher = newSearcher(reader);
                MappedFieldType ft = simpleMappedFieldType();
                assertThat(
                    searcher.count(
                        ft.rangeQuery("2020-07-22T15:36:21.356Z", "2020-07-23T00:00:00.000Z", true, true, null, null, null, mockContext())
                    ),
                    equalTo(1)
                );
                assertThat(
                    searcher.count(
                        ft.rangeQuery("2020-07-22T00:00:00.00Z", "2020-07-22T15:36:21.354Z", true, true, null, null, null, mockContext())
                    ),
                    equalTo(2)
                );
                assertThat(
                    searcher.count(ft.rangeQuery(1595432181351L, 1595432181356L, true, true, null, null, null, mockContext())),
                    equalTo(3)
                );
                assertThat(
                    searcher.count(
                        ft.rangeQuery("2020-07-22T15:36:21.356Z", "2020-07-23T00:00:00.000Z", true, false, null, null, null, mockContext())
                    ),
                    equalTo(1)
                );
                assertThat(
                    searcher.count(
                        ft.rangeQuery("2020-07-22T15:36:21.356Z", "2020-07-23T00:00:00.000Z", false, false, null, null, null, mockContext())
                    ),
                    equalTo(0)
                );
                checkBadDate(
                    () -> searcher.count(
                        ft.rangeQuery(
                            "2020-07-22(-■_■)00:00:00.000Z",
                            "2020-07-23(-■_■)00:00:00.000Z",
                            false,
                            false,
                            null,
                            null,
                            null,
                            mockContext()
                        )
                    )
                );
                assertThat(
                    searcher.count(
                        coolFormattedFieldType().rangeQuery(
                            "2020-07-22(-■_■)00:00:00.000Z",
                            "2020-07-23(-■_■)00:00:00.000Z",
                            false,
                            false,
                            null,
                            null,
                            null,
                            mockContext()
                        )
                    ),
                    equalTo(3)
                );
            }
        }
    }

    @Override
    public void testRangeQueryIsExpensive() throws IOException {
        checkExpensiveQuery(
            (ft, ctx) -> ft.rangeQuery(randomLong(), randomLong(), randomBoolean(), randomBoolean(), null, null, null, ctx)
        );
    }

    @Override
    public void testTermQuery() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181354]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181355]}"))));
            try (DirectoryReader reader = iw.getReader()) {
                IndexSearcher searcher = newSearcher(reader);
                assertThat(searcher.count(simpleMappedFieldType().termQuery("2020-07-22T15:36:21.354Z", mockContext())), equalTo(1));
                assertThat(searcher.count(simpleMappedFieldType().termQuery("1595432181355", mockContext())), equalTo(1));
                assertThat(searcher.count(simpleMappedFieldType().termQuery(1595432181354L, mockContext())), equalTo(1));
                assertThat(searcher.count(simpleMappedFieldType().termQuery(2595432181354L, mockContext())), equalTo(0));
                assertThat(
                    searcher.count(build("add_days", Map.of("days", 1)).termQuery("2020-07-23T15:36:21.354Z", mockContext())),
                    equalTo(1)
                );
                checkBadDate(() -> searcher.count(simpleMappedFieldType().termQuery("2020-07-22(-■_■)15:36:21.354Z", mockContext())));
                assertThat(searcher.count(coolFormattedFieldType().termQuery("2020-07-22(-■_■)15:36:21.354Z", mockContext())), equalTo(1));
            }
        }
    }

    @Override
    public void testTermQueryIsExpensive() throws IOException {
        checkExpensiveQuery((ft, ctx) -> ft.termQuery(0, ctx));
    }

    @Override
    public void testTermsQuery() throws IOException {
        try (Directory directory = newDirectory(); RandomIndexWriter iw = new RandomIndexWriter(random(), directory)) {
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181354]}"))));
            iw.addDocument(List.of(new StoredField("_source", new BytesRef("{\"timestamp\": [1595432181355]}"))));
            try (DirectoryReader reader = iw.getReader()) {
                MappedFieldType ft = simpleMappedFieldType();
                IndexSearcher searcher = newSearcher(reader);
                assertThat(searcher.count(ft.termsQuery(List.of("2020-07-22T15:36:21.354Z"), mockContext())), equalTo(1));
                assertThat(searcher.count(ft.termsQuery(List.of("1595432181354"), mockContext())), equalTo(1));
                assertThat(searcher.count(ft.termsQuery(List.of(1595432181354L), mockContext())), equalTo(1));
                assertThat(searcher.count(ft.termsQuery(List.of(2595432181354L), mockContext())), equalTo(0));
                assertThat(searcher.count(ft.termsQuery(List.of(1595432181354L, 2595432181354L), mockContext())), equalTo(1));
                assertThat(searcher.count(ft.termsQuery(List.of(2595432181354L, 1595432181354L), mockContext())), equalTo(1));
                assertThat(searcher.count(ft.termsQuery(List.of(1595432181355L, 1595432181354L), mockContext())), equalTo(2));
                checkBadDate(
                    () -> searcher.count(
                        simpleMappedFieldType().termsQuery(
                            List.of("2020-07-22T15:36:21.354Z", "2020-07-22(-■_■)15:36:21.354Z"),
                            mockContext()
                        )
                    )
                );
                assertThat(
                    searcher.count(
                        coolFormattedFieldType().termsQuery(
                            List.of("2020-07-22(-■_■)15:36:21.354Z", "2020-07-22(-■_■)15:36:21.355Z"),
                            mockContext()
                        )
                    ),
                    equalTo(2)
                );
            }
        }
    }

    @Override
    public void testTermsQueryIsExpensive() throws IOException {
        checkExpensiveQuery((ft, ctx) -> ft.termsQuery(List.of(0), ctx));
    }

    @Override
    protected ScriptDateMappedFieldType simpleMappedFieldType() throws IOException {
        return build("read_timestamp");
    }

    private ScriptDateMappedFieldType coolFormattedFieldType() throws IOException {
        return build(simpleMappedFieldType().script, DateFormatter.forPattern("yyyy-MM-dd(-■_■)HH:mm:ss.SSSz||epoch_millis"));
    }

    @Override
    protected String runtimeType() {
        return "date";
    }

    private static ScriptDateMappedFieldType build(String code) throws IOException {
        return build(code, Map.of());
    }

    private static ScriptDateMappedFieldType build(String code, Map<String, Object> params) throws IOException {
        return build(new Script(ScriptType.INLINE, "test", code, params), DateFieldMapper.DEFAULT_DATE_TIME_FORMATTER);
    }

    private static ScriptDateMappedFieldType build(Script script, DateFormatter dateTimeFormatter) throws IOException {
        ScriptPlugin scriptPlugin = new ScriptPlugin() {
            @Override
            public ScriptEngine getScriptEngine(Settings settings, Collection<ScriptContext<?>> contexts) {
                return new ScriptEngine() {
                    @Override
                    public String getType() {
                        return "test";
                    }

                    @Override
                    public Set<ScriptContext<?>> getSupportedContexts() {
                        return Set.of(DateScriptFieldScript.CONTEXT);
                    }

                    @Override
                    public <FactoryType> FactoryType compile(
                        String name,
                        String code,
                        ScriptContext<FactoryType> context,
                        Map<String, String> params
                    ) {
                        @SuppressWarnings("unchecked")
                        FactoryType factory = (FactoryType) factory(code);
                        return factory;
                    }

                    private DateScriptFieldScript.Factory factory(String code) {
                        switch (code) {
                            case "read_timestamp":
                                return (fieldName, params, lookup, formatter) -> ctx -> new DateScriptFieldScript(
                                    fieldName,
                                    params,
                                    lookup,
                                    formatter,
                                    ctx
                                ) {
                                    @Override
                                    public void execute() {
                                        for (Object timestamp : (List<?>) getSource().get("timestamp")) {
                                            DateScriptFieldScript.Parse parse = new DateScriptFieldScript.Parse(this);
                                            emit(parse.parse(timestamp));
                                        }
                                    }
                                };
                            case "add_days":
                                return (fieldName, params, lookup, formatter) -> ctx -> new DateScriptFieldScript(
                                    fieldName,
                                    params,
                                    lookup,
                                    formatter,
                                    ctx
                                ) {
                                    @Override
                                    public void execute() {
                                        for (Object timestamp : (List<?>) getSource().get("timestamp")) {
                                            long epoch = (Long) timestamp;
                                            ZonedDateTime dt = ZonedDateTime.ofInstant(Instant.ofEpochMilli(epoch), ZoneId.of("UTC"));
                                            dt = dt.plus(((Number) params.get("days")).longValue(), ChronoUnit.DAYS);
                                            emit(toEpochMilli(dt));
                                        }
                                    }
                                };
                            default:
                                throw new IllegalArgumentException("unsupported script [" + code + "]");
                        }
                    }
                };
            }
        };
        ScriptModule scriptModule = new ScriptModule(Settings.EMPTY, List.of(scriptPlugin, new RuntimeFields()));
        try (ScriptService scriptService = new ScriptService(Settings.EMPTY, scriptModule.engines, scriptModule.contexts)) {
            DateScriptFieldScript.Factory factory = scriptService.compile(script, DateScriptFieldScript.CONTEXT);
            return new ScriptDateMappedFieldType("test", script, factory, dateTimeFormatter, emptyMap());
        }
    }

    private void checkExpensiveQuery(BiConsumer<ScriptDateMappedFieldType, QueryShardContext> queryBuilder) throws IOException {
        ScriptDateMappedFieldType ft = simpleMappedFieldType();
        Exception e = expectThrows(ElasticsearchException.class, () -> queryBuilder.accept(ft, mockContext(false)));
        assertThat(
            e.getMessage(),
            equalTo("queries cannot be executed against [runtime] fields while [search.allow_expensive_queries] is set to [false].")
        );
    }

    private void checkBadDate(ThrowingRunnable queryBuilder) {
        Exception e = expectThrows(ElasticsearchParseException.class, queryBuilder);
        assertThat(e.getMessage(), containsString("failed to parse date field"));
    }
}
