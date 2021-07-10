/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.action.service;

import org.elasticsearch.Version;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class GetServiceAccountCredentialsResponseTests extends ESTestCase {

    public void testSerialisation() throws IOException {
        final GetServiceAccountCredentialsResponse original = createTestInstance();
        final BytesStreamOutput out = new BytesStreamOutput();
        original.writeTo(out);
        final GetServiceAccountCredentialsResponse deserialized = new GetServiceAccountCredentialsResponse(out.bytes().streamInput());

        assertThat(original.getPrincipal(), equalTo(deserialized.getPrincipal()));
        assertThat(original.getTokenInfos(), equalTo(deserialized.getTokenInfos()));
        assertThat(original.getFileTokensResponse().getTokenInfos(), equalTo(deserialized.getFileTokensResponse().getTokenInfos()));
    }

    private GetServiceAccountCredentialsResponse createTestInstance() {
        final String principal = randomAlphaOfLengthBetween(3, 8) + "/" + randomAlphaOfLengthBetween(3, 8);
        final List<TokenInfo> indexTokenInfos = IntStream.range(0, randomIntBetween(0, 10))
            .mapToObj(i -> TokenInfo.indexToken(randomAlphaOfLengthBetween(3, 8)))
            .collect(Collectors.toUnmodifiableList());
        final GetServiceAccountFileTokensResponse fileTokensResponse = randomGetServiceAccountFileTokensResponse();
        return new GetServiceAccountCredentialsResponse(principal, indexTokenInfos, fileTokensResponse);
    }

    @SuppressWarnings("unchecked")
    public void testToXContent() throws IOException {
        final GetServiceAccountCredentialsResponse response = createTestInstance();
        final Collection<TokenInfo> tokenInfos = response.getTokenInfos();

        XContentBuilder builder = XContentFactory.jsonBuilder();
        response.toXContent(builder, ToXContent.EMPTY_PARAMS);
        final Map<String, Object> responseMap = XContentHelper.convertToMap(BytesReference.bytes(builder),
            false, builder.contentType()).v2();

        assertThat(responseMap.get("service_account"), equalTo(response.getPrincipal()));
        assertThat(responseMap.get("count"), equalTo(tokenInfos.size()));

        final Map<String, TokenInfo> nameToTokenInfos = tokenInfos.stream()
            .collect(Collectors.toMap(TokenInfo::getName, Function.identity()));

        final Map<String, Object> tokens = (Map<String, Object>) responseMap.get("tokens");
        assertNotNull(tokens);
        tokens.keySet().forEach(k -> assertThat(nameToTokenInfos.remove(k).getSource(), equalTo(TokenInfo.TokenSource.INDEX)));


        final Map<String, Object> fileTokens = (Map<String, Object>) responseMap.get("file_tokens");
        assertNotNull(fileTokens);
        fileTokens.forEach((key, value) -> {
            if (key.equals("_nodes")) {
                final Map<String, Object> nodesContent = (Map<String, Object>) value;
                assertThat(nodesContent.get("successful"), equalTo(response.getFileTokensResponse().getNodes().size()));
                assertThat(nodesContent.get("failed"), equalTo(response.getFileTokensResponse().failures().size()));
            } else {
                final Map<String, Object> tokenContent = (Map<String, Object>) value;
                assertThat(tokenContent.get("nodes"), equalTo(nameToTokenInfos.get(key).getNodeNames()));
                assertThat(nameToTokenInfos.remove(key).getSource(), equalTo(TokenInfo.TokenSource.FILE));
            }
        });
        assertThat(nameToTokenInfos, is(anEmptyMap()));
    }

    private GetServiceAccountFileTokensResponse randomGetServiceAccountFileTokensResponse() {
        final ClusterName clusterName = new ClusterName(randomAlphaOfLength(8));
        final int total = randomIntBetween(1, 5);
        final int nFailures = randomIntBetween(0, 5);
        final String[] tokenNames = randomArray(0, 10, String[]::new, () -> randomAlphaOfLengthBetween(3, 8));

        final ArrayList<GetServiceAccountFileTokensResponse.Node> nodes = new ArrayList<>();
        for (int i = 0; i < total - nFailures; i++) {
            final GetServiceAccountFileTokensResponse.Node node = randomNodeResponse(tokenNames, i);
            nodes.add(node);
        }

        final ArrayList<FailedNodeException> failures = new ArrayList<>();
        for (int i = 0; i < nFailures; i++) {
            final FailedNodeException e = randomFailedNodeException(i);
            failures.add(e);
        }
        return new GetServiceAccountFileTokensResponse(clusterName, nodes, failures);
    }

    private FailedNodeException randomFailedNodeException(int i) {
        return new FailedNodeException(randomAlphaOfLength(9) + i, randomAlphaOfLength(20), new NoSuchFileException("service_tokens"));
    }

    private GetServiceAccountFileTokensResponse.Node randomNodeResponse(String[] tokenNames, int i) {
        final DiscoveryNode discoveryNode = new DiscoveryNode(
            randomAlphaOfLength(8) + i,
            new TransportAddress(TransportAddress.META_ADDRESS, 9300),
            Version.CURRENT);
        return new GetServiceAccountFileTokensResponse.Node(
            discoveryNode,
            randomSubsetOf(randomIntBetween(0, tokenNames.length), tokenNames).toArray(String[]::new));
    }
}
