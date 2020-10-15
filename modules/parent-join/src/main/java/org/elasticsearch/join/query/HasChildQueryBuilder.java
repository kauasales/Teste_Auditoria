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
package org.elasticsearch.join.query;

import org.apache.lucene.search.MatchNoDocsQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.join.ScoreMode;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.ParsingException;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.lucene.search.Queries;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.index.fielddata.plain.SortedSetOrdinalsIndexFieldData;
import org.elasticsearch.index.mapper.MappedFieldType;
import org.elasticsearch.index.query.AbstractQueryBuilder;
import org.elasticsearch.index.query.InnerHitBuilder;
import org.elasticsearch.index.query.InnerHitContextBuilder;
import org.elasticsearch.index.query.NestedQueryBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryRewriteContext;
import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.index.query.QueryShardException;
import org.elasticsearch.join.mapper.Joiner;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.elasticsearch.search.SearchService.ALLOW_EXPENSIVE_QUERIES;

/**
 * A query builder for {@code has_child} query.
 */
public class HasChildQueryBuilder extends AbstractQueryBuilder<HasChildQueryBuilder> {
    public static final String NAME = "has_child";

    /**
     * The default maximum number of children that are required to match for the parent to be considered a match.
     */
    public static final int DEFAULT_MAX_CHILDREN = Integer.MAX_VALUE;
    /**
     * The default minimum number of children that are required to match for the parent to be considered a match.
     */
    public static final int DEFAULT_MIN_CHILDREN = 1;

    /**
     * The default value for ignore_unmapped.
     */
    public static final boolean DEFAULT_IGNORE_UNMAPPED = false;

    private static final ParseField QUERY_FIELD = new ParseField("query");
    private static final ParseField TYPE_FIELD = new ParseField("type");
    private static final ParseField MAX_CHILDREN_FIELD = new ParseField("max_children");
    private static final ParseField MIN_CHILDREN_FIELD = new ParseField("min_children");
    private static final ParseField SCORE_MODE_FIELD = new ParseField("score_mode");
    private static final ParseField INNER_HITS_FIELD = new ParseField("inner_hits");
    private static final ParseField IGNORE_UNMAPPED_FIELD = new ParseField("ignore_unmapped");

    private final QueryBuilder query;
    private final String type;
    private final ScoreMode scoreMode;
    private InnerHitBuilder innerHitBuilder;
    private int minChildren = DEFAULT_MIN_CHILDREN;
    private int maxChildren = DEFAULT_MAX_CHILDREN;
    private boolean ignoreUnmapped = false;

    public HasChildQueryBuilder(String type, QueryBuilder query, ScoreMode scoreMode) {
        this(type, query, DEFAULT_MIN_CHILDREN, DEFAULT_MAX_CHILDREN, scoreMode, null);
    }

    private HasChildQueryBuilder(String type, QueryBuilder query, int minChildren, int maxChildren, ScoreMode scoreMode,
                                InnerHitBuilder innerHitBuilder) {
        this.type = requireValue(type, "[" + NAME + "] requires 'type' field");
        this.query = requireValue(query, "[" + NAME + "] requires 'query' field");
        this.scoreMode = requireValue(scoreMode, "[" + NAME + "] requires 'score_mode' field");
        this.innerHitBuilder = innerHitBuilder;
        this.minChildren = minChildren;
        this.maxChildren = maxChildren;
    }

    /**
     * Read from a stream.
     */
    public HasChildQueryBuilder(StreamInput in) throws IOException {
        super(in);
        type = in.readString();
        minChildren = in.readInt();
        maxChildren = in.readInt();
        scoreMode = ScoreMode.values()[in.readVInt()];
        query = in.readNamedWriteable(QueryBuilder.class);
        innerHitBuilder = in.readOptionalWriteable(InnerHitBuilder::new);
        ignoreUnmapped = in.readBoolean();
    }

    @Override
    protected void doWriteTo(StreamOutput out) throws IOException {
        out.writeString(type);
        out.writeInt(minChildren);
        out.writeInt(maxChildren);
        out.writeVInt(scoreMode.ordinal());
        out.writeNamedWriteable(query);
        out.writeOptionalWriteable(innerHitBuilder);
        out.writeBoolean(ignoreUnmapped);
    }

    /**
     * Defines the minimum number of children that are required to match for the parent to be considered a match and
     * the maximum number of children that are required to match for the parent to be considered a match.
     */
    public HasChildQueryBuilder minMaxChildren(int minChildren, int maxChildren) {
        if (minChildren <= 0) {
            throw new IllegalArgumentException("[" + NAME + "] requires positive 'min_children' field");
        }
        if (maxChildren <= 0) {
            throw new IllegalArgumentException("[" + NAME + "] requires positive 'max_children' field");
        }
        if (maxChildren < minChildren) {
            throw new IllegalArgumentException("[" + NAME + "] 'max_children' is less than 'min_children'");
        }
        this.minChildren = minChildren;
        this.maxChildren = maxChildren;
        return this;
    }

    /**
     * Returns inner hit definition in the scope of this query and reusing the defined type and query.
     */
    public InnerHitBuilder innerHit() {
        return innerHitBuilder;
    }

    public HasChildQueryBuilder innerHit(InnerHitBuilder innerHit) {
        this.innerHitBuilder = innerHit;
        innerHitBuilder.setIgnoreUnmapped(ignoreUnmapped);
        return this;
    }

    /**
     * Returns the children query to execute.
     */
    public QueryBuilder query() {
        return query;
    }

    /**
     * Returns the child type
     */
    public String childType() {
        return type;
    }

    /**
     * Returns how the scores from the matching child documents are mapped into the parent document.
     */
    public ScoreMode scoreMode() {
        return scoreMode;
    }

    /**
     * Returns the minimum number of children that are required to match for the parent to be considered a match.
     * The default is {@value #DEFAULT_MIN_CHILDREN}
     */
    public int minChildren() {
        return minChildren;
    }

    /**
     * Returns the maximum number of children that are required to match for the parent to be considered a match.
     * The default is {@value #DEFAULT_MAX_CHILDREN}
     */
    public int maxChildren() { return maxChildren; }

    /**
     * Sets whether the query builder should ignore unmapped types (and run a
     * {@link MatchNoDocsQuery} in place of this query) or throw an exception if
     * the type is unmapped.
     */
    public HasChildQueryBuilder ignoreUnmapped(boolean ignoreUnmapped) {
        this.ignoreUnmapped = ignoreUnmapped;
        if (innerHitBuilder!= null ){
            innerHitBuilder.setIgnoreUnmapped(ignoreUnmapped);
        }
        return this;
    }

    /**
     * Gets whether the query builder will ignore unmapped types (and run a
     * {@link MatchNoDocsQuery} in place of this query) or throw an exception if
     * the type is unmapped.
     */
    public boolean ignoreUnmapped() {
        return ignoreUnmapped;
    }

    @Override
    protected void doXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(NAME);
        builder.field(QUERY_FIELD.getPreferredName());
        query.toXContent(builder, params);
        builder.field(TYPE_FIELD.getPreferredName(), type);
        builder.field(SCORE_MODE_FIELD.getPreferredName(), NestedQueryBuilder.scoreModeAsString(scoreMode));
        builder.field(MIN_CHILDREN_FIELD.getPreferredName(), minChildren);
        builder.field(MAX_CHILDREN_FIELD.getPreferredName(), maxChildren);
        builder.field(IGNORE_UNMAPPED_FIELD.getPreferredName(), ignoreUnmapped);
        printBoostAndQueryName(builder);
        if (innerHitBuilder != null) {
            builder.field(INNER_HITS_FIELD.getPreferredName(), innerHitBuilder, params);
        }
        builder.endObject();
    }

    public static HasChildQueryBuilder fromXContent(XContentParser parser) throws IOException {
        float boost = AbstractQueryBuilder.DEFAULT_BOOST;
        String childType = null;
        ScoreMode scoreMode = ScoreMode.None;
        int minChildren = HasChildQueryBuilder.DEFAULT_MIN_CHILDREN;
        int maxChildren = HasChildQueryBuilder.DEFAULT_MAX_CHILDREN;
        boolean ignoreUnmapped = DEFAULT_IGNORE_UNMAPPED;
        String queryName = null;
        InnerHitBuilder innerHitBuilder = null;
        String currentFieldName = null;
        XContentParser.Token token;
        QueryBuilder iqb = null;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else if (token == XContentParser.Token.START_OBJECT) {
                if (QUERY_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    iqb = parseInnerQueryBuilder(parser);
                } else if (INNER_HITS_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    innerHitBuilder = InnerHitBuilder.fromXContent(parser);
                } else {
                    throw new ParsingException(parser.getTokenLocation(), "[has_child] query does not support [" + currentFieldName + "]");
                }
            } else if (token.isValue()) {
                if (TYPE_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    childType = parser.text();
                } else if (SCORE_MODE_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    scoreMode = NestedQueryBuilder.parseScoreMode(parser.text());
                } else if (AbstractQueryBuilder.BOOST_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    boost = parser.floatValue();
                } else if (MIN_CHILDREN_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    minChildren = parser.intValue(true);
                } else if (MAX_CHILDREN_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    maxChildren = parser.intValue(true);
                } else if (IGNORE_UNMAPPED_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    ignoreUnmapped = parser.booleanValue();
                } else if (AbstractQueryBuilder.NAME_FIELD.match(currentFieldName, parser.getDeprecationHandler())) {
                    queryName = parser.text();
                } else {
                    throw new ParsingException(parser.getTokenLocation(), "[has_child] query does not support [" + currentFieldName + "]");
                }
            }
        }
        HasChildQueryBuilder hasChildQueryBuilder = new HasChildQueryBuilder(childType, iqb, scoreMode);
        hasChildQueryBuilder.minMaxChildren(minChildren, maxChildren);
        hasChildQueryBuilder.queryName(queryName);
        hasChildQueryBuilder.boost(boost);
        hasChildQueryBuilder.ignoreUnmapped(ignoreUnmapped);
        if (innerHitBuilder != null) {
            hasChildQueryBuilder.innerHit(innerHitBuilder);
        }
        return hasChildQueryBuilder;
    }

    @Override
    public String getWriteableName() {
        return NAME;
    }

    @Override
    protected Query doToQuery(QueryShardContext context) throws IOException {
        if (context.allowExpensiveQueries() == false) {
            throw new ElasticsearchException("[joining] queries cannot be executed when '" +
                    ALLOW_EXPENSIVE_QUERIES.getKey() + "' is set to false.");
        }

        Joiner joiner = Joiner.getJoiner(context);
        if (joiner == null) {
            if (ignoreUnmapped) {
                return new MatchNoDocsQuery();
            } else {
                throw new QueryShardException(context, "[" + NAME + "] no join field has been configured");
            }
        }

        if (joiner.childTypeExists(type) == false) {
            if (ignoreUnmapped) {
                return new MatchNoDocsQuery();
            } else {
                throw new QueryShardException(context, "[" + NAME + "] join field [" + joiner.getJoinField() +
                    "] doesn't hold [" + type + "] as a child");
            }
        }

        String parentJoinField = joiner.parentJoinField(type);
        if (context.isFieldMapped(parentJoinField) == false) {
            if (ignoreUnmapped) {
                return new MatchNoDocsQuery();
            }
            throw new QueryShardException(context, "[" + NAME + "] no parent join field [" + parentJoinField + "] configured");
        }

        Query parentFilter = joiner.parentFilter(type);
        Query childFilter = joiner.filter(type);
        Query filteredQuery = Queries.filtered(doToQuery(context), childFilter);
        MappedFieldType ft = context.getFieldType(parentJoinField);
        final SortedSetOrdinalsIndexFieldData fieldData = context.getForField(ft);
        return new LateParsingQuery(parentFilter, filteredQuery, minChildren, maxChildren,
            parentJoinField, scoreMode, fieldData, context.getSearchSimilarity());
    }

    @Override
    protected boolean doEquals(HasChildQueryBuilder that) {
        return Objects.equals(query, that.query)
                && Objects.equals(type, that.type)
                && Objects.equals(scoreMode, that.scoreMode)
                && Objects.equals(minChildren, that.minChildren)
                && Objects.equals(maxChildren, that.maxChildren)
                && Objects.equals(innerHitBuilder, that.innerHitBuilder)
                && Objects.equals(ignoreUnmapped, that.ignoreUnmapped);
    }

    @Override
    protected int doHashCode() {
        return Objects.hash(query, type, scoreMode, minChildren, maxChildren, innerHitBuilder, ignoreUnmapped);
    }

    @Override
    protected QueryBuilder doRewrite(QueryRewriteContext queryShardContext) throws IOException {
        QueryBuilder rewrittenQuery = query.rewrite(queryShardContext);
        if (rewrittenQuery != query) {
            HasChildQueryBuilder hasChildQueryBuilder =
                new HasChildQueryBuilder(type, rewrittenQuery, minChildren, maxChildren, scoreMode, innerHitBuilder);
            hasChildQueryBuilder.ignoreUnmapped(ignoreUnmapped);
            return hasChildQueryBuilder;
        }
        return this;
    }

    @Override
    protected void extractInnerHitBuilders(Map<String, InnerHitContextBuilder> innerHits) {
        if (innerHitBuilder != null) {
            String name = innerHitBuilder.getName() != null ? innerHitBuilder.getName() : type;
            if (innerHits.containsKey(name)) {
                throw new IllegalArgumentException("[inner_hits] already contains an entry for key [" + name + "]");
            }

            Map<String, InnerHitContextBuilder> children = new HashMap<>();
            InnerHitContextBuilder.extractInnerHits(query, children);
            InnerHitContextBuilder innerHitContextBuilder =
                new ParentChildInnerHitContextBuilder(type, true, query, innerHitBuilder, children);
            innerHits.put(name, innerHitContextBuilder);
        }
    }
}
