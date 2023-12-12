/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */
package fixture.s3;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.UUIDs;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.bytes.CompositeBytesReference;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.io.Streams;
import org.elasticsearch.common.regex.Regex;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.SuppressForbidden;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.rest.RestUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.w3c.dom.Node.ELEMENT_NODE;

/**
 * Minimal HTTP handler that acts as a S3 compliant server
 */
@SuppressForbidden(reason = "this test uses a HttpServer to emulate an S3 endpoint")
public class S3HttpHandler implements HttpHandler {

    private static final Logger logger = LogManager.getLogger(S3HttpHandler.class);

    private final String bucket;
    private final String path;

    private final ConcurrentMap<String, BytesReference> blobs = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, MultipartUpload> uploads = new ConcurrentHashMap<>();

    public S3HttpHandler(final String bucket) {
        this(bucket, null);
    }

    public S3HttpHandler(final String bucket, @Nullable final String basePath) {
        this.bucket = Objects.requireNonNull(bucket);
        this.path = bucket + (basePath != null && basePath.isEmpty() == false ? "/" + basePath : "");
    }

    @Override
    public void handle(final HttpExchange exchange) throws IOException {
        final String request = exchange.getRequestMethod() + " " + exchange.getRequestURI().toString();
        if (request.startsWith("GET") || request.startsWith("HEAD") || request.startsWith("DELETE")) {
            int read = exchange.getRequestBody().read();
            assert read == -1 : "Request body should have been empty but saw [" + read + "]";
        }
        try {
            if (Regex.simpleMatch("HEAD /" + path + "/*", request)) {
                final BytesReference blob = blobs.get(exchange.getRequestURI().getPath());
                if (blob == null) {
                    exchange.sendResponseHeaders(RestStatus.NOT_FOUND.getStatus(), -1);
                } else {
                    exchange.sendResponseHeaders(RestStatus.OK.getStatus(), -1);
                }
            } else if (Regex.simpleMatch("GET /" + bucket + "/?uploads&prefix=*", request)) {
                final Map<String, String> params = new HashMap<>();
                RestUtils.decodeQueryString(exchange.getRequestURI().getQuery(), 0, params);

                final var prefix = params.get("prefix");

                final var uploadsList = new StringBuilder();
                uploadsList.append("<?xml version='1.0' encoding='UTF-8'?>");
                uploadsList.append("<ListMultipartUploadsResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>");
                uploadsList.append("<Bucket>").append(bucket).append("</Bucket>");
                uploadsList.append("<KeyMarker />");
                uploadsList.append("<UploadIdMarker />");
                uploadsList.append("<NextKeyMarker>--unused--</NextKeyMarker>");
                uploadsList.append("<NextUploadIdMarker />");
                uploadsList.append("<Delimiter />");
                uploadsList.append("<Prefix>").append(prefix).append("</Prefix>");
                uploadsList.append("<MaxUploads>10000</MaxUploads>");
                uploadsList.append("<IsTruncated>false</IsTruncated>");

                for (final var multipartUpload : uploads.values()) {
                    if (multipartUpload.getPath().startsWith(prefix)) {
                        multipartUpload.appendXml(uploadsList);
                    }
                }

                uploadsList.append("</ListMultipartUploadsResult>");

                byte[] response = uploadsList.toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/xml");
                exchange.sendResponseHeaders(RestStatus.OK.getStatus(), response.length);
                exchange.getResponseBody().write(response);

            } else if (Regex.simpleMatch("POST /" + path + "/*?uploads", request)) {
                validateStorageClass(exchange);

                final var upload = new MultipartUpload(
                    UUIDs.randomBase64UUID(),
                    exchange.getRequestURI().getPath().substring(bucket.length() + 2)
                );
                uploads.put(upload.getUploadId(), upload);

                final var uploadResult = new StringBuilder();
                uploadResult.append("<?xml version='1.0' encoding='UTF-8'?>");
                uploadResult.append("<InitiateMultipartUploadResult>");
                uploadResult.append("<Bucket>").append(bucket).append("</Bucket>");
                uploadResult.append("<Key>").append(upload.getPath()).append("</Key>");
                uploadResult.append("<UploadId>").append(upload.getUploadId()).append("</UploadId>");
                uploadResult.append("</InitiateMultipartUploadResult>");

                byte[] response = uploadResult.toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/xml");
                exchange.sendResponseHeaders(RestStatus.OK.getStatus(), response.length);
                exchange.getResponseBody().write(response);

            } else if (Regex.simpleMatch("PUT /" + path + "/*?uploadId=*&partNumber=*", request)) {
                final Map<String, String> params = new HashMap<>();
                RestUtils.decodeQueryString(exchange.getRequestURI().getQuery(), 0, params);

                final var upload = uploads.get(params.get("uploadId"));
                if (upload == null) {
                    exchange.sendResponseHeaders(RestStatus.NOT_FOUND.getStatus(), -1);
                } else {
                    final Tuple<String, BytesReference> blob = parseRequestBody(exchange);
                    upload.addPart(blob.v1(), blob.v2());
                    exchange.getResponseHeaders().add("ETag", blob.v1());
                    exchange.sendResponseHeaders(RestStatus.OK.getStatus(), -1);
                }

            } else if (Regex.simpleMatch("POST /" + path + "/*?uploadId=*", request)) {

                final Map<String, String> params = new HashMap<>();
                RestUtils.decodeQueryString(exchange.getRequestURI().getQuery(), 0, params);
                final var upload = uploads.remove(params.get("uploadId"));
                if (upload == null) {
                    exchange.sendResponseHeaders(RestStatus.NOT_FOUND.getStatus(), -1);
                } else {
                    final var blobContents = upload.complete(extractPartEtags(Streams.readFully(exchange.getRequestBody())));
                    blobs.put(exchange.getRequestURI().getPath(), blobContents);

                    byte[] response = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        + "<CompleteMultipartUploadResult>\n"
                        + "<Bucket>"
                        + bucket
                        + "</Bucket>\n"
                        + "<Key>"
                        + exchange.getRequestURI().getPath()
                        + "</Key>\n"
                        + "</CompleteMultipartUploadResult>").getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/xml");
                    exchange.sendResponseHeaders(RestStatus.OK.getStatus(), response.length);
                    exchange.getResponseBody().write(response);
                }
            } else if (Regex.simpleMatch("DELETE /" + path + "/*?uploadId=*", request)) {
                final Map<String, String> params = new HashMap<>();
                RestUtils.decodeQueryString(exchange.getRequestURI().getQuery(), 0, params);
                final var upload = uploads.remove(params.get("uploadId"));
                exchange.sendResponseHeaders((upload == null ? RestStatus.NOT_FOUND : RestStatus.NO_CONTENT).getStatus(), -1);

            } else if (Regex.simpleMatch("PUT /" + path + "/*", request)) {
                validateStorageClass(exchange);

                final Tuple<String, BytesReference> blob = parseRequestBody(exchange);
                blobs.put(exchange.getRequestURI().toString(), blob.v2());
                exchange.getResponseHeaders().add("ETag", blob.v1());
                exchange.sendResponseHeaders(RestStatus.OK.getStatus(), -1);

            } else if (Regex.simpleMatch("GET /" + bucket + "/?prefix=*", request)) {
                final Map<String, String> params = new HashMap<>();
                RestUtils.decodeQueryString(exchange.getRequestURI().getQuery(), 0, params);
                if (params.get("list-type") != null) {
                    throw new AssertionError("Test must be adapted for GET Bucket (List Objects) Version 2");
                }

                final StringBuilder list = new StringBuilder();
                list.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                list.append("<ListBucketResult>");
                final String prefix = params.get("prefix");
                if (prefix != null) {
                    list.append("<Prefix>").append(prefix).append("</Prefix>");
                }
                final Set<String> commonPrefixes = new HashSet<>();
                final String delimiter = params.get("delimiter");
                if (delimiter != null) {
                    list.append("<Delimiter>").append(delimiter).append("</Delimiter>");
                }
                for (Map.Entry<String, BytesReference> blob : blobs.entrySet()) {
                    if (prefix != null && blob.getKey().startsWith("/" + bucket + "/" + prefix) == false) {
                        continue;
                    }
                    String blobPath = blob.getKey().replace("/" + bucket + "/", "");
                    if (delimiter != null) {
                        int fromIndex = (prefix != null ? prefix.length() : 0);
                        int delimiterPosition = blobPath.indexOf(delimiter, fromIndex);
                        if (delimiterPosition > 0) {
                            commonPrefixes.add(blobPath.substring(0, delimiterPosition) + delimiter);
                            continue;
                        }
                    }
                    list.append("<Contents>");
                    list.append("<Key>").append(blobPath).append("</Key>");
                    list.append("<Size>").append(blob.getValue().length()).append("</Size>");
                    list.append("</Contents>");
                }
                if (commonPrefixes.isEmpty() == false) {
                    list.append("<CommonPrefixes>");
                    commonPrefixes.forEach(commonPrefix -> list.append("<Prefix>").append(commonPrefix).append("</Prefix>"));
                    list.append("</CommonPrefixes>");

                }
                list.append("</ListBucketResult>");

                byte[] response = list.toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/xml");
                exchange.sendResponseHeaders(RestStatus.OK.getStatus(), response.length);
                exchange.getResponseBody().write(response);

            } else if (Regex.simpleMatch("GET /" + path + "/*", request)) {
                final BytesReference blob = blobs.get(exchange.getRequestURI().toString());
                if (blob != null) {
                    final String range = exchange.getRequestHeaders().getFirst("Range");
                    if (range == null) {
                        exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
                        exchange.sendResponseHeaders(RestStatus.OK.getStatus(), blob.length());
                        blob.writeTo(exchange.getResponseBody());
                    } else {
                        final Matcher matcher = Pattern.compile("^bytes=([0-9]+)-([0-9]+)$").matcher(range);
                        if (matcher.matches() == false) {
                            throw new AssertionError("Bytes range does not match expected pattern: " + range);
                        }

                        final int start = Integer.parseInt(matcher.group(1));
                        final int end = Integer.parseInt(matcher.group(2));

                        final BytesReference rangeBlob = blob.slice(start, end + 1 - start);
                        exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
                        exchange.getResponseHeaders()
                            .add("Content-Range", String.format(Locale.ROOT, "bytes %d-%d/%d", start, end, rangeBlob.length()));
                        exchange.sendResponseHeaders(RestStatus.OK.getStatus(), rangeBlob.length());
                        rangeBlob.writeTo(exchange.getResponseBody());
                    }
                } else {
                    exchange.sendResponseHeaders(RestStatus.NOT_FOUND.getStatus(), -1);
                }

            } else if (Regex.simpleMatch("DELETE /" + path + "/*", request)) {
                int deletions = 0;
                for (Iterator<Map.Entry<String, BytesReference>> iterator = blobs.entrySet().iterator(); iterator.hasNext();) {
                    Map.Entry<String, BytesReference> blob = iterator.next();
                    if (blob.getKey().startsWith(exchange.getRequestURI().toString())) {
                        iterator.remove();
                        deletions++;
                    }
                }
                exchange.sendResponseHeaders((deletions > 0 ? RestStatus.OK : RestStatus.NO_CONTENT).getStatus(), -1);

            } else if (Regex.simpleMatch("POST /" + bucket + "/?delete", request)) {
                final String requestBody = Streams.copyToString(new InputStreamReader(exchange.getRequestBody(), UTF_8));

                final StringBuilder deletes = new StringBuilder();
                deletes.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                deletes.append("<DeleteResult>");
                for (Iterator<Map.Entry<String, BytesReference>> iterator = blobs.entrySet().iterator(); iterator.hasNext();) {
                    Map.Entry<String, BytesReference> blob = iterator.next();
                    String key = blob.getKey().replace("/" + bucket + "/", "");
                    if (requestBody.contains("<Key>" + key + "</Key>")) {
                        deletes.append("<Deleted><Key>").append(key).append("</Key></Deleted>");
                        iterator.remove();
                    }
                }
                deletes.append("</DeleteResult>");

                byte[] response = deletes.toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/xml");
                exchange.sendResponseHeaders(RestStatus.OK.getStatus(), response.length);
                exchange.getResponseBody().write(response);

            } else {
                exchange.sendResponseHeaders(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), -1);
            }
        } finally {
            exchange.close();
        }
    }

    public Map<String, BytesReference> blobs() {
        return blobs;
    }

    private static final Pattern chunkSignaturePattern = Pattern.compile("^([0-9a-z]+);chunk-signature=([^\\r\\n]*)$");

    private static Tuple<String, BytesReference> parseRequestBody(final HttpExchange exchange) throws IOException {
        try {
            final BytesReference bytesReference;

            final String headerDecodedContentLength = exchange.getRequestHeaders().getFirst("x-amz-decoded-content-length");
            if (headerDecodedContentLength == null) {
                bytesReference = Streams.readFully(exchange.getRequestBody());
            } else {
                BytesReference requestBody = Streams.readFully(exchange.getRequestBody());
                int chunkIndex = 0;
                final List<BytesReference> chunks = new ArrayList<>();

                while (true) {
                    chunkIndex += 1;

                    final int headerLength = requestBody.indexOf((byte) '\n', 0) + 1; // includes terminating \r\n
                    if (headerLength == 0) {
                        throw new IllegalStateException("header of chunk [" + chunkIndex + "] was not terminated");
                    }
                    if (headerLength > 150) {
                        throw new IllegalStateException(
                            "header of chunk [" + chunkIndex + "] was too long at [" + headerLength + "] bytes"
                        );
                    }
                    if (headerLength < 3) {
                        throw new IllegalStateException(
                            "header of chunk [" + chunkIndex + "] was too short at [" + headerLength + "] bytes"
                        );
                    }
                    if (requestBody.get(headerLength - 1) != '\n' || requestBody.get(headerLength - 2) != '\r') {
                        throw new IllegalStateException("header of chunk [" + chunkIndex + "] not terminated with [\\r\\n]");
                    }

                    final String header = requestBody.slice(0, headerLength - 2).utf8ToString();
                    final Matcher matcher = chunkSignaturePattern.matcher(header);
                    if (matcher.find() == false) {
                        throw new IllegalStateException(
                            "header of chunk [" + chunkIndex + "] did not match expected pattern: [" + header + "]"
                        );
                    }
                    final int chunkSize = Integer.parseUnsignedInt(matcher.group(1), 16);

                    if (requestBody.get(headerLength + chunkSize) != '\r' || requestBody.get(headerLength + chunkSize + 1) != '\n') {
                        throw new IllegalStateException("chunk [" + chunkIndex + "] not terminated with [\\r\\n]");
                    }

                    if (chunkSize != 0) {
                        chunks.add(requestBody.slice(headerLength, chunkSize));
                    }

                    final int toSkip = headerLength + chunkSize + 2;
                    requestBody = requestBody.slice(toSkip, requestBody.length() - toSkip);

                    if (chunkSize == 0) {
                        break;
                    }
                }

                bytesReference = CompositeBytesReference.of(chunks.toArray(new BytesReference[0]));

                if (bytesReference.length() != Integer.parseInt(headerDecodedContentLength)) {
                    throw new IllegalStateException(
                        "Something went wrong when parsing the chunked request "
                            + "[bytes read="
                            + bytesReference.length()
                            + ", expected="
                            + headerDecodedContentLength
                            + "]"
                    );
                }
            }
            return Tuple.tuple(MessageDigests.toHexString(MessageDigests.digest(bytesReference, MessageDigests.md5())), bytesReference);
        } catch (Exception e) {
            logger.error("exception in parseRequestBody", e);
            exchange.sendResponseHeaders(500, 0);
            try (PrintStream printStream = new PrintStream(exchange.getResponseBody())) {
                printStream.println(e);
                e.printStackTrace(printStream);
            }
            throw e;
        }
    }

    static List<String> extractPartEtags(BytesReference completeMultipartUploadBody) {
        try {
            final var document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(completeMultipartUploadBody.streamInput());
            final var parts = document.getElementsByTagName("Part");
            final var result = new ArrayList<String>(parts.getLength());
            for (int partIndex = 0; partIndex < parts.getLength(); partIndex++) {
                final var part = parts.item(partIndex);
                String etag = null;
                int partNumber = -1;
                final var childNodes = part.getChildNodes();
                for (int childIndex = 0; childIndex < childNodes.getLength(); childIndex++) {
                    final var childNode = childNodes.item(childIndex);
                    if (childNode.getNodeType() == ELEMENT_NODE) {
                        if (childNode.getNodeName().equals("ETag")) {
                            etag = childNode.getTextContent();
                        } else if (childNode.getNodeName().equals("PartNumber")) {
                            partNumber = Integer.parseInt(childNode.getTextContent()) - 1;
                        }
                    }
                }

                if (etag == null || partNumber == -1) {
                    throw new IllegalStateException("incomplete part details");
                }

                while (result.size() <= partNumber) {
                    result.add(null);
                }

                if (result.get(partNumber) != null) {
                    throw new IllegalStateException("duplicate part found");
                }
                result.set(partNumber, etag);
            }

            if (result.stream().anyMatch(Objects::isNull)) {
                throw new IllegalStateException("missing part");
            }

            return result;
        } catch (Exception e) {
            throw ExceptionsHelper.convertToRuntime(e);
        }
    }

    public static void sendError(final HttpExchange exchange, final RestStatus status, final String errorCode, final String message)
        throws IOException {
        final Headers headers = exchange.getResponseHeaders();
        headers.add("Content-Type", "application/xml");

        final String requestId = exchange.getRequestHeaders().getFirst("x-amz-request-id");
        if (requestId != null) {
            headers.add("x-amz-request-id", requestId);
        }

        if (errorCode == null || "HEAD".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(status.getStatus(), -1L);
            exchange.close();
        } else {
            final byte[] response = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error>"
                + "<Code>"
                + errorCode
                + "</Code>"
                + "<Message>"
                + message
                + "</Message>"
                + "<RequestId>"
                + requestId
                + "</RequestId>"
                + "</Error>").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status.getStatus(), response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        }
    }

    MultipartUpload getUpload(String uploadId) {
        return uploads.get(uploadId);
    }

    protected void validateStorageClass(String path, String storageClass) {}

    private void validateStorageClass(HttpExchange exchange) {
        validateStorageClass(
            exchange.getRequestURI().getPath().substring(bucket.length() + 2),
            exchange.getRequestHeaders().getFirst("x-amz-storage-class")
        );
    }
}
