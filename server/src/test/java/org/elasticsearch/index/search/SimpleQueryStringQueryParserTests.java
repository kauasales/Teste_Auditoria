package org.elasticsearch.index.search;

import org.elasticsearch.test.ESTestCase;

public class SimpleQueryStringQueryParserTests extends ESTestCase {

    public void testEqualsSettings() {
        SimpleQueryStringQueryParser.Settings settings1 = new SimpleQueryStringQueryParser.Settings();
        SimpleQueryStringQueryParser.Settings settings2 = new SimpleQueryStringQueryParser.Settings();
        String s = "Some random other object";
        assertEquals(settings1, settings1);
        assertEquals(settings1, settings2);
        assertNotEquals(settings1, null);
        assertNotEquals(settings1, s);

        settings2.lenient(!settings1.lenient());
        assertNotEquals(settings1, settings2);

        settings2 = new SimpleQueryStringQueryParser.Settings();
        settings2.analyzeWildcard(!settings1.analyzeWildcard());
        assertNotEquals(settings1, settings2);

        settings2 = new SimpleQueryStringQueryParser.Settings();
        settings2.quoteFieldSuffix("a");
        assertNotEquals(settings1, settings2);

        settings2 = new SimpleQueryStringQueryParser.Settings();
        settings2.autoGenerateSynonymsPhraseQuery(!settings1.autoGenerateSynonymsPhraseQuery());
        assertNotEquals(settings1, settings2);

        settings2 = new SimpleQueryStringQueryParser.Settings();
        settings2.fuzzyPrefixLength(settings1.fuzzyPrefixLength() + 1);
        assertNotEquals(settings1, settings2);

        settings2 = new SimpleQueryStringQueryParser.Settings();
        settings2.fuzzyMaxExpansions(settings1.fuzzyMaxExpansions() + 1);
        assertNotEquals(settings1, settings2);

        settings2 = new SimpleQueryStringQueryParser.Settings();
        settings2.fuzzyTranspositions(!settings1.fuzzyTranspositions());
        assertNotEquals(settings1, settings2);
    }
}
