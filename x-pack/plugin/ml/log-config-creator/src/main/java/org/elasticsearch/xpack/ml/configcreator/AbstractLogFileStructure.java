/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.ml.configcreator;

import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.Terminal.Verbosity;
import org.elasticsearch.grok.Grok;
import org.elasticsearch.xpack.ml.configcreator.TimestampFormatFinder.TimestampMatch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.AccessControlException;
import java.util.Collection;
import java.util.Locale;
import java.util.Objects;
import java.util.SortedMap;
import java.util.stream.Collectors;

public abstract class AbstractLogFileStructure {

    protected static final boolean IS_WINDOWS = System.getProperty("os.name").startsWith("Windows");
    protected static final String DEFAULT_TIMESTAMP_FIELD = "@timestamp";

    // NUMBER Grok pattern doesn't support scientific notation, so we extend it
    private static final Grok NUMBER_GROK = new Grok(Grok.getBuiltinPatterns(), "^%{NUMBER}(?:[eE][+-]?[0-3]?[0-9]{1,2})?$");
    private static final Grok IP_GROK = new Grok(Grok.getBuiltinPatterns(), "^%{IP}$");
    private static final int KEYWORD_MAX_LEN = 256;
    private static final int KEYWORD_MAX_SPACES = 5;

    private static final String FILEBEAT_PATH_TEMPLATE = "  paths:\n" +
        "   - '%s'\n";
    private static final String FILEBEAT_ENCODING_TEMPLATE = "  encoding: '%s'\n";
    private static final String FILEBEAT_MULTILINE_CONFIG_TEMPLATE = "  multiline.pattern: '%s'\n" +
        "  multiline.negate: true\n" +
        "  multiline.match: after\n";
    private static final String FILEBEAT_EXCLUDE_LINES_TEMPLATE = "  exclude_lines: ['^%s']\n";

    private static final String LOGSTASH_ENCODING_TEMPLATE = "      charset => \"%s\"\n";
    private static final String LOGSTASH_MULTILINE_CODEC_TEMPLATE = "    codec => multiline {\n" +
        "%s" +
        "      pattern => \"%s\"\n" +
        "      negate => \"true\"\n" +
        "      what => \"previous\"\n" +
        "      auto_flush_interval => 1\n" +
        "    }\n";
    private static final String LOGSTASH_LINE_CODEC_TEMPLATE = "    codec => line {\n" +
        "%s" +
        "    }\n";
    private static final String LOGSTASH_FILE_INPUT_TEMPLATE = "  file {\n" +
        "    type => \"%s\"\n" +
        "    path => [ '%s' ]\n" +
        "    start_position => beginning\n" +
        "    ignore_older => 0\n" +
        "%s" +
        "    sincedb_path => \"" + (IS_WINDOWS ? "NUL" : "/dev/null") + "\"\n" +
        "  }\n";

    // These next two are needed because Joda will throw an error if asked to parse fractional seconds
    // more granular than milliseconds, so we need to truncate the fractional part to 3 digits
    private static final String LOGSTASH_FRACTIONAL_SECONDS_GSUB_TEMPLATE = "  mutate {\n" +
        "    gsub => [ %s%s%s, \"([:.,]\\d{3})\\d*\", \"\\1\" ]\n" +
        "  }\n";
    private static final String INGEST_PIPELINE_FRACTIONAL_SECONDS_GSUB_TEMPLATE = ",\n" +
        "      \"gsub\": {\n" +
        "        \"field\": \"%s\",\n" +
        "        \"pattern\": \"([:.,]\\d{3})\\d*\",\n" +
        "        \"replacement\": \"$1\"\n" +
        "      }";

    private static final String FIELD_MAPPING_TEMPLATE = "        \"%s\": {\n" +
        "          \"type\": \"%s\"\n" +
        "        }";
    private static final String INDEX_MAPPINGS_TEMPLATE = "PUT %s\n" +
        "{\n" +
        "  \"mappings\": {\n" +
        "    \"_doc\": {\n" +
        "      \"properties\": {\n" +
        "%s\n" +
        "      }\n" +
        "    }\n" +
        "  }\n" +
        "}\n";

    protected final Terminal terminal;
    protected final String sampleFileName;
    protected final String indexName;
    protected final String typeName;
    protected final String charsetName;
    private String preambleComment = "";

    protected AbstractLogFileStructure(Terminal terminal, String sampleFileName, String indexName, String typeName, String charsetName) {
        this.terminal = Objects.requireNonNull(terminal);
        this.sampleFileName = Objects.requireNonNull(sampleFileName);
        this.indexName = Objects.requireNonNull(indexName);
        this.typeName = Objects.requireNonNull(typeName);
        this.charsetName = Objects.requireNonNull(charsetName);
    }

    protected void writeConfigFile(Path directory, String fileName, String contents) throws IOException {
        Path fullPath = directory.resolve(typeName + "-" + fileName);
        Files.write(fullPath, (preambleComment + contents).getBytes(StandardCharsets.UTF_8));
        terminal.println("Wrote config file " + fullPath);
        try {
            Files.setPosixFilePermissions(fullPath, PosixFilePermissions.fromString(fileName.endsWith(".sh") ? "rwxr-xr-x" : "rw-r--r--"));
        } catch (AccessControlException | UnsupportedOperationException e) {
            // * For AccessControlException, assume we're running in an ESTestCase unit test, which will have security manager enabled.
            // * For UnsupportedOperationException, assume we're on Windows.
            // In neither situation is it a problem that the file permissions can't be set.
        }
    }

    protected void writeRestCallConfigs(Path directory, String consoleFileName, String consoleCommand) throws IOException {
        writeConfigFile(directory, consoleFileName, consoleCommand);
        String curlCommand = "curl -H 'Content-Type: application/json' -X " +
            consoleCommand.replaceFirst(" ", " http://localhost:9200/").replaceFirst("\n", " -d '\n") + "'\n";
        writeConfigFile(directory, consoleFileName.replaceFirst("\\.console$", ".sh"), curlCommand);
    }

    protected void writeMappingsConfigs(Path directory, SortedMap<String, String> fieldTypes) throws IOException {
        terminal.println(Verbosity.VERBOSE, "---");
        String fieldTypeMappings = fieldTypes.entrySet().stream().map(entry -> String.format(Locale.ROOT, FIELD_MAPPING_TEMPLATE,
            entry.getKey(), entry.getValue())).collect(Collectors.joining(",\n"));
        writeRestCallConfigs(directory, "index-mappings.console", String.format(Locale.ROOT, INDEX_MAPPINGS_TEMPLATE, indexName,
            fieldTypeMappings));
    }

    protected static String bestLogstashQuoteFor(String str) {
        return (str.indexOf('"') >= 0) ? "'" : "\""; // NB: fails if field name contains both types of quotes
    }

    protected String makeFilebeatInputOptions(String multilineRegex, String excludeLinesRegex) {
        StringBuilder builder = new StringBuilder(String.format(Locale.ROOT, FILEBEAT_PATH_TEMPLATE, sampleFileName));
        if (charsetName.equals(StandardCharsets.UTF_8.name()) == false) {
            builder.append(String.format(Locale.ROOT, FILEBEAT_ENCODING_TEMPLATE, charsetName.toLowerCase(Locale.ROOT)));
        }
        if (multilineRegex != null) {
            builder.append(String.format(Locale.ROOT, FILEBEAT_MULTILINE_CONFIG_TEMPLATE, multilineRegex));
        }
        if (excludeLinesRegex != null) {
            builder.append(String.format(Locale.ROOT, FILEBEAT_EXCLUDE_LINES_TEMPLATE, excludeLinesRegex));

        }
        return builder.toString();
    }

    protected String makeLogstashFileInput(String multilineRegex) {
        return String.format(Locale.ROOT, LOGSTASH_FILE_INPUT_TEMPLATE, typeName, sampleFileName, makeLogstashFileCodec(multilineRegex));
    }

    private String makeLogstashFileCodec(String multilineRegex) {

        String encodingConfig =
            (charsetName.equals(StandardCharsets.UTF_8.name())) ? "" : String.format(Locale.ROOT, LOGSTASH_ENCODING_TEMPLATE, charsetName);
        if (multilineRegex == null) {
            if (encodingConfig.isEmpty()) {
                return "";
            }
            return String.format(Locale.ROOT, LOGSTASH_LINE_CODEC_TEMPLATE, encodingConfig);
        }

        return String.format(Locale.ROOT, LOGSTASH_MULTILINE_CODEC_TEMPLATE, encodingConfig, multilineRegex);
    }

    protected String makeLogstashFractionalSecondsGsubFilter(String timeFieldName, TimestampMatch timestampMatch) {

        String fieldQuote = bestLogstashQuoteFor(timeFieldName);
        return timestampMatch.hasFractionalComponentSmallerThanMillisecond ?
            String.format(Locale.ROOT, LOGSTASH_FRACTIONAL_SECONDS_GSUB_TEMPLATE, fieldQuote, timeFieldName, fieldQuote) : "";
    }

    protected String makeIngestPipelineFractionalSecondsGsubFilter(String timeFieldName, TimestampMatch timestampMatch) {

        return timestampMatch.hasFractionalComponentSmallerThanMillisecond ?
            String.format(Locale.ROOT, INGEST_PIPELINE_FRACTIONAL_SECONDS_GSUB_TEMPLATE, timeFieldName) : "";
    }

    static String guessScalarMapping(Terminal terminal, String fieldName, Collection<String> fieldValues) {

        if (fieldValues.stream().allMatch(value -> "true".equals(value) || "false".equals(value))) {
            return "boolean";
        }

        TimestampMatch timestampMatch = null;
        for (String fieldValue : fieldValues) {
            if (timestampMatch == null) {
                timestampMatch = TimestampFormatFinder.findFirstFullMatch(fieldValue);
                if (timestampMatch == null) {
                    break;
                }
            } else if (TimestampFormatFinder.findFirstFullMatch(fieldValue, timestampMatch.candidateIndex) != timestampMatch) {
                break;
            }
        }
        if (timestampMatch != null) {
            return "date";
        }

        if (fieldValues.stream().allMatch(NUMBER_GROK::match)) {
            try {
                fieldValues.forEach(Long::parseLong);
                return "long";
            } catch (NumberFormatException e) {
                terminal.println(Verbosity.VERBOSE,
                    "Rejecting type 'long' for field [" + fieldName + "] due to parse failure: [" + e.getMessage() + "]");
            }
            try {
                fieldValues.forEach(Double::parseDouble);
                return "double";
            } catch (NumberFormatException e) {
                terminal.println(Verbosity.VERBOSE,
                    "Rejecting type 'double' for field [" + fieldName + "] due to parse failure: [" + e.getMessage() + "]");
            }
        }

        else if (fieldValues.stream().allMatch(IP_GROK::match)) {
            return "ip";
        }

        if (fieldValues.stream().anyMatch(AbstractStructuredLogFileStructure::isMoreLikelyTextThanKeyword)) {
            return "text";
        }

        return "keyword";
    }

    static boolean isMoreLikelyTextThanKeyword(String str) {
        int length = str.length();
        return length > KEYWORD_MAX_LEN || length - str.replaceAll("\\s", "").length() > KEYWORD_MAX_SPACES;
    }

    protected void createPreambleComment(String preamble) {
        if (preamble == null || preamble.isEmpty()) {
            preambleComment = "";
        } else {
            preambleComment = "# This config was derived from a sample that began with:\n" +
                "#\n" +
                "# " + preamble.replaceFirst("\n$", "").replace("\n", "\n# ") + "\n" +
                "#\n";
        }
    }
}
