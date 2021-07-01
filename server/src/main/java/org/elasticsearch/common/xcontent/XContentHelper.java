/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.common.xcontent;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.common.compress.Compressor;
import org.elasticsearch.common.compress.CompressorFactory;
import org.elasticsearch.common.xcontent.ToXContent.Params;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@SuppressWarnings("unchecked")
public class XContentHelper {

    /**
     * Creates a parser based on the bytes provided
     * @deprecated use {@link #createParser(NamedXContentRegistry, DeprecationHandler, BytesReference, XContentType)}
     * to avoid content type auto-detection
     */
    @Deprecated
    public static XContentParser createParser(NamedXContentRegistry xContentRegistry, DeprecationHandler deprecationHandler,
                                              BytesReference bytes) throws IOException {
        Compressor compressor = CompressorFactory.compressor(bytes);
        if (compressor != null) {
            InputStream compressedInput = compressor.threadLocalInputStream(bytes.streamInput());
            if (compressedInput.markSupported() == false) {
                compressedInput = new BufferedInputStream(compressedInput);
            }
            final XContentType contentType = XContentFactory.xContentType(compressedInput);
            return XContentFactory.xContent(contentType).createParser(xContentRegistry, deprecationHandler, compressedInput);
        } else {
            return XContentFactory.xContent(xContentType(bytes)).createParser(xContentRegistry, deprecationHandler, bytes.streamInput());
        }
    }

    /**
     * Creates a parser for the bytes using the supplied content-type
     */
    public static XContentParser createParser(NamedXContentRegistry xContentRegistry, DeprecationHandler deprecationHandler,
                                              BytesReference bytes, XContentType xContentType) throws IOException {
        Objects.requireNonNull(xContentType);
        Compressor compressor = CompressorFactory.compressor(bytes);
        if (compressor != null) {
            InputStream compressedInput = compressor.threadLocalInputStream(bytes.streamInput());
            if (compressedInput.markSupported() == false) {
                compressedInput = new BufferedInputStream(compressedInput);
            }
            return XContentFactory.xContent(xContentType).createParser(xContentRegistry, deprecationHandler, compressedInput);
        } else {
            if (bytes.hasArray()) {
                return xContentType.xContent().createParser(
                        xContentRegistry, deprecationHandler, bytes.array(), bytes.arrayOffset(), bytes.length());
            }
            return xContentType.xContent().createParser(xContentRegistry, deprecationHandler, bytes.streamInput());
        }
    }

    /**
     * Converts the given bytes into a map that is optionally ordered.
     * <p>
     * Important: This can lose precision on numbers with a decimal point. It
     * converts numbers like {@code "n": 1234.567} to a {@code double} which
     * only has 52 bits of precision in the mantissa. This will come up most
     * frequently when folks write nanosecond precision dates as a decimal
     * number.
     * @deprecated this method relies on auto-detection of content type. Use {@link #convertToMap(BytesReference, boolean, XContentType)}
     *             instead with the proper {@link XContentType}
     */
    @Deprecated
    public static Tuple<XContentType, Map<String, Object>> convertToMap(BytesReference bytes, boolean ordered)
            throws ElasticsearchParseException {
        return convertToMap(bytes, ordered, null);
    }

    /**
     * Converts the given bytes into a map that is optionally ordered. The provided {@link XContentType} must be non-null.
     * <p>
     * Important: This can lose precision on numbers with a decimal point. It
     * converts numbers like {@code "n": 1234.567} to a {@code double} which
     * only has 52 bits of precision in the mantissa. This will come up most
     * frequently when folks write nanosecond precision dates as a decimal
     * number.
     */
    public static Tuple<XContentType, Map<String, Object>> convertToMap(BytesReference bytes, boolean ordered, XContentType xContentType)
        throws ElasticsearchParseException {
        try {
            final XContentType contentType;
            InputStream input;
            Compressor compressor = CompressorFactory.compressor(bytes);
            if (compressor != null) {
                InputStream compressedStreamInput = compressor.threadLocalInputStream(bytes.streamInput());
                if (compressedStreamInput.markSupported() == false) {
                    compressedStreamInput = new BufferedInputStream(compressedStreamInput);
                }
                input = compressedStreamInput;
                contentType = xContentType != null ? xContentType : XContentFactory.xContentType(input);
            } else if (bytes.hasArray()) {
                final byte[] raw = bytes.array();
                final int offset = bytes.arrayOffset();
                final int length = bytes.length();
                contentType = xContentType != null ? xContentType : XContentFactory.xContentType(raw, offset, length);
                return new Tuple<>(Objects.requireNonNull(contentType),
                        convertToMap(XContentFactory.xContent(contentType), raw, offset, length, ordered));
            } else {
                input = bytes.streamInput();
                contentType = xContentType != null ? xContentType : XContentFactory.xContentType(input);
            }
            try (InputStream stream = input) {
                return new Tuple<>(Objects.requireNonNull(contentType),
                    convertToMap(XContentFactory.xContent(contentType), stream, ordered));
            }
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to parse content to map", e);
        }
    }

    /**
     * Convert a string in some {@link XContent} format to a {@link Map}. Throws an {@link ElasticsearchParseException} if there is any
     * error.
     */
    public static Map<String, Object> convertToMap(XContent xContent, String string, boolean ordered) throws ElasticsearchParseException {
        // It is safe to use EMPTY here because this never uses namedObject
        try (XContentParser parser = xContent.createParser(NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION, string)) {
            return ordered ? parser.mapOrdered() : parser.map();
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to parse content to map", e);
        }
    }

    /**
     * Convert a string in some {@link XContent} format to a {@link Map}. Throws an {@link ElasticsearchParseException} if there is any
     * error. Note that unlike {@link #convertToMap(BytesReference, boolean)}, this doesn't automatically uncompress the input.
     */
    public static Map<String, Object> convertToMap(XContent xContent, InputStream input, boolean ordered)
            throws ElasticsearchParseException {
        // It is safe to use EMPTY here because this never uses namedObject
        try (XContentParser parser = xContent.createParser(NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION, input)) {
            return ordered ? parser.mapOrdered() : parser.map();
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to parse content to map", e);
        }
    }

    /**
     * Convert a byte array in some {@link XContent} format to a {@link Map}. Throws an {@link ElasticsearchParseException} if there is any
     * error. Note that unlike {@link #convertToMap(BytesReference, boolean)}, this doesn't automatically uncompress the input.
     */
    public static Map<String, Object> convertToMap(XContent xContent, byte[] bytes, int offset, int length, boolean ordered)
            throws ElasticsearchParseException {
        // It is safe to use EMPTY here because this never uses namedObject
        try (XContentParser parser = xContent.createParser(NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION, bytes, offset, length)) {
            return ordered ? parser.mapOrdered() : parser.map();
        } catch (IOException e) {
            throw new ElasticsearchParseException("Failed to parse content to map", e);
        }
    }

    @Deprecated
    public static String convertToJson(BytesReference bytes, boolean reformatJson) throws IOException {
        return convertToJson(bytes, reformatJson, false);
    }

    @Deprecated
    public static String convertToJson(BytesReference bytes, boolean reformatJson, boolean prettyPrint) throws IOException {
        return convertToJson(bytes, reformatJson, prettyPrint, XContentFactory.xContentType(bytes.toBytesRef().bytes));
    }

    public static String convertToJson(BytesReference bytes, boolean reformatJson, XContentType xContentType) throws IOException {
        return convertToJson(bytes, reformatJson, false, xContentType);
    }

    /**
     * Accepts a JSON string, parses it and prints it without pretty-printing it. This is useful
     * where a piece of JSON is formatted for legibility, but needs to be stripped of unnecessary
     * whitespace e.g. for comparison in a test.
     *
     * @param json the JSON to format
     * @return reformatted JSON
     * @throws IOException if the reformatting fails, e.g. because the JSON is not well-formed
     */
    public static String stripWhitespace(String json) throws IOException {
        return convertToJson(new BytesArray(json), true, XContentType.JSON);
    }

    public static String convertToJson(BytesReference bytes, boolean reformatJson, boolean prettyPrint, XContentType xContentType)
        throws IOException {
        Objects.requireNonNull(xContentType);
        if (xContentType == XContentType.JSON && reformatJson == false) {
            return bytes.utf8ToString();
        }

        // It is safe to use EMPTY here because this never uses namedObject
        if (bytes.hasArray()) {
            try (XContentParser parser = XContentFactory.xContent(xContentType).createParser(NamedXContentRegistry.EMPTY,
                         DeprecationHandler.THROW_UNSUPPORTED_OPERATION, bytes.array(), bytes.arrayOffset(), bytes.length())) {
                return toJsonString(prettyPrint, parser);
            }
        } else {
            try (InputStream stream = bytes.streamInput();
                 XContentParser parser = XContentFactory.xContent(xContentType).createParser(NamedXContentRegistry.EMPTY,
                         DeprecationHandler.THROW_UNSUPPORTED_OPERATION, stream)) {
                return toJsonString(prettyPrint, parser);
            }
        }
    }

    private static String toJsonString(boolean prettyPrint, XContentParser parser) throws IOException {
        parser.nextToken();
        XContentBuilder builder = XContentFactory.jsonBuilder();
        if (prettyPrint) {
            builder.prettyPrint();
        }
        builder.copyCurrentStructure(parser);
        return Strings.toString(builder);
    }

    /**
     * Updates the provided changes into the source. If the key exists in the changes, it overrides the one in source
     * unless both are Maps, in which case it recursively updated it.
     *
     * @param source                 the original map to be updated
     * @param changes                the changes to update into updated
     * @param checkUpdatesAreUnequal should this method check if updates to the same key (that are not both maps) are
     *                               unequal?  This is just a .equals check on the objects, but that can take some time on long strings.
     * @return true if the source map was modified
     */
    public static boolean update(Map<String, Object> source, Map<String, Object> changes, boolean checkUpdatesAreUnequal) {
        boolean modified = false;
        for (Map.Entry<String, Object> changesEntry : changes.entrySet()) {
            if (source.containsKey(changesEntry.getKey()) == false) {
                // safe to copy, change does not exist in source
                source.put(changesEntry.getKey(), changesEntry.getValue());
                modified = true;
                continue;
            }
            Object old = source.get(changesEntry.getKey());
            if (old instanceof Map && changesEntry.getValue() instanceof Map) {
                // recursive merge maps
                modified |= update((Map<String, Object>) source.get(changesEntry.getKey()),
                        (Map<String, Object>) changesEntry.getValue(), checkUpdatesAreUnequal && modified == false);
                continue;
            }
            // update the field
            source.put(changesEntry.getKey(), changesEntry.getValue());
            if (modified) {
                continue;
            }
            if (checkUpdatesAreUnequal == false) {
                modified = true;
                continue;
            }
            modified = Objects.equals(old, changesEntry.getValue()) == false;
        }
        return modified;
    }

    /**
     * Merges the defaults provided as the second parameter into the content of the first. Only does recursive merge
     * for inner maps.
     */
    public static void mergeDefaults(Map<String, Object> content, Map<String, Object> defaults) {
        for (Map.Entry<String, Object> defaultEntry : defaults.entrySet()) {
            if (content.containsKey(defaultEntry.getKey()) == false) {
                // copy it over, it does not exists in the content
                content.put(defaultEntry.getKey(), defaultEntry.getValue());
            } else {
                // in the content and in the default, only merge compound ones (maps)
                if (content.get(defaultEntry.getKey()) instanceof Map && defaultEntry.getValue() instanceof Map) {
                    mergeDefaults((Map<String, Object>) content.get(defaultEntry.getKey()), (Map<String, Object>) defaultEntry.getValue());
                } else if (content.get(defaultEntry.getKey()) instanceof List && defaultEntry.getValue() instanceof List) {
                    List defaultList = (List) defaultEntry.getValue();
                    List contentList = (List) content.get(defaultEntry.getKey());

                    List mergedList = new ArrayList();
                    if (allListValuesAreMapsOfOne(defaultList) && allListValuesAreMapsOfOne(contentList)) {
                        // all are in the form of [ {"key1" : {}}, {"key2" : {}} ], merge based on keys
                        Map<String, Map<String, Object>> processed = new LinkedHashMap<>();
                        for (Object o : contentList) {
                            Map<String, Object> map = (Map<String, Object>) o;
                            Map.Entry<String, Object> entry = map.entrySet().iterator().next();
                            processed.put(entry.getKey(), map);
                        }
                        for (Object o : defaultList) {
                            Map<String, Object> map = (Map<String, Object>) o;
                            Map.Entry<String, Object> entry = map.entrySet().iterator().next();
                            if (processed.containsKey(entry.getKey())) {
                                mergeDefaults(processed.get(entry.getKey()), map);
                            } else {
                                // put the default entries after the content ones.
                                processed.put(entry.getKey(), map);
                            }
                        }
                        for (Map<String, Object> map : processed.values()) {
                            mergedList.add(map);
                        }
                    } else {
                        // if both are lists, simply combine them, first the defaults, then the content
                        // just make sure not to add the same value twice
                        mergedList.addAll(defaultList);
                        for (Object o : contentList) {
                            if (mergedList.contains(o) == false) {
                                mergedList.add(o);
                            }
                        }
                    }
                    content.put(defaultEntry.getKey(), mergedList);
                }
            }
        }
    }

    private static boolean allListValuesAreMapsOfOne(List list) {
        for (Object o : list) {
            if ((o instanceof Map) == false) {
                return false;
            }
            if (((Map) o).size() != 1) {
                return false;
            }
        }
        return true;
    }

    /**
     * Writes a "raw" (bytes) field, handling cases where the bytes are compressed, and tries to optimize writing using
     * {@link XContentBuilder#rawField(String, InputStream)}.
     * @deprecated use {@link #writeRawField(String, BytesReference, XContentType, XContentBuilder, Params)} to avoid content type
     * auto-detection
     */
    @Deprecated
    public static void writeRawField(String field, BytesReference source, XContentBuilder builder,
                                     ToXContent.Params params) throws IOException {
        Compressor compressor = CompressorFactory.compressor(source);
        if (compressor != null) {
            try (InputStream compressedStreamInput = compressor.threadLocalInputStream(source.streamInput())) {
                builder.rawField(field, compressedStreamInput);
            }
        } else {
            try (InputStream stream = source.streamInput()) {
                builder.rawField(field, stream);
            }
        }
    }

    /**
     * Writes a "raw" (bytes) field, handling cases where the bytes are compressed, and tries to optimize writing using
     * {@link XContentBuilder#rawField(String, InputStream, XContentType)}.
     */
    public static void writeRawField(String field, BytesReference source, XContentType xContentType, XContentBuilder builder,
                                     ToXContent.Params params) throws IOException {
        Objects.requireNonNull(xContentType);
        Compressor compressor = CompressorFactory.compressor(source);
        if (compressor != null) {
            try (InputStream compressedStreamInput = compressor.threadLocalInputStream(source.streamInput())) {
                builder.rawField(field, compressedStreamInput, xContentType);
            }
        } else {
            try (InputStream stream = source.streamInput()) {
                builder.rawField(field, stream, xContentType);
            }
        }
    }

    /**
     * Returns the bytes that represent the XContent output of the provided {@link ToXContent} object, using the provided
     * {@link XContentType}. Wraps the output into a new anonymous object according to the value returned
     * by the {@link ToXContent#isFragment()} method returns.
     */
    public static BytesReference toXContent(ToXContent toXContent, XContentType xContentType, boolean humanReadable) throws IOException {
        return toXContent(toXContent, xContentType, ToXContent.EMPTY_PARAMS, humanReadable);
    }

    /**
     * Returns the bytes that represent the XContent output of the provided {@link ToXContent} object, using the provided
     * {@link XContentType}. Wraps the output into a new anonymous object according to the value returned
     * by the {@link ToXContent#isFragment()} method returns.
     */
    public static BytesReference toXContent(ToXContent toXContent, XContentType xContentType, Params params,
                                            boolean humanReadable) throws IOException {
        try (XContentBuilder builder = XContentBuilder.builder(xContentType.xContent())) {
            builder.humanReadable(humanReadable);
            if (toXContent.isFragment()) {
                builder.startObject();
            }
            toXContent.toXContent(builder, params);
            if (toXContent.isFragment()) {
                builder.endObject();
            }
            return BytesReference.bytes(builder);
        }
    }

    /**
     * Guesses the content type based on the provided bytes.
     *
     * @deprecated the content type should not be guessed except for few cases where we effectively don't know the content type.
     * The REST layer should move to reading the Content-Type header instead. There are other places where auto-detection may be needed.
     * This method is deprecated to prevent usages of it from spreading further without specific reasons.
     */
    @Deprecated
    public static XContentType xContentType(BytesReference bytes) {
        if (bytes.hasArray()) {
            return XContentFactory.xContentType(bytes.array(), bytes.arrayOffset(), bytes.length());
        }
        try {
            final InputStream inputStream = bytes.streamInput();
            assert inputStream.markSupported();
            return XContentFactory.xContentType(inputStream);
        } catch (IOException e) {
            assert false : "Should not happen, we're just reading bytes from memory";
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Returns the contents of an object as an unparsed BytesReference
     *
     * This is useful for things like mappings where we're copying bytes around but don't
     * actually need to parse their contents, and so avoids building large maps of maps
     * unnecessarily
     */
    public static BytesReference childBytes(XContentParser parser) throws IOException {
        if (parser.currentToken() != XContentParser.Token.START_OBJECT) {
            if (parser.nextToken() != XContentParser.Token.START_OBJECT) {
                throw new XContentParseException(parser.getTokenLocation(),
                    "Expected [START_OBJECT] but got [" + parser.currentToken() + "]");
            }
        }
        XContentBuilder builder = XContentBuilder.builder(parser.contentType().xContent());
        builder.copyCurrentStructure(parser);
        return BytesReference.bytes(builder);
    }
}
