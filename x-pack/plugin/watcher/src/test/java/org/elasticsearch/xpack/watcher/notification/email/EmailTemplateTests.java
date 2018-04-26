/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */
package org.elasticsearch.xpack.watcher.notification.email;

import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.watcher.common.text.TextTemplate;
import org.elasticsearch.xpack.watcher.test.MockTextTemplateEngine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EmailTemplateTests extends ESTestCase {

    public void testEmailTemplateParserSelfGenerated() throws Exception {
        TextTemplate from = randomFrom(new TextTemplate("from@from.com"), null);
        List<TextTemplate> addresses = new ArrayList<>();
        for( int i = 0; i < randomIntBetween(1, 5); ++i){
            addresses.add(new TextTemplate("address" + i + "@test.com"));
        }
        TextTemplate[] possibleList = addresses.toArray(new TextTemplate[addresses.size()]);
        TextTemplate[] replyTo = randomFrom(possibleList, null);
        TextTemplate[] to = randomFrom(possibleList, null);
        TextTemplate[] cc = randomFrom(possibleList, null);
        TextTemplate[] bcc = randomFrom(possibleList, null);
        TextTemplate priority = new TextTemplate(randomFrom(Email.Priority.values()).name());

        TextTemplate subjectTemplate = new TextTemplate("Templated Subject {{foo}}");
        TextTemplate textBodyTemplate = new TextTemplate("Templated Body {{foo}}");

        TextTemplate htmlBodyTemplate = new TextTemplate("Templated Html Body <script>nefarious scripting</script>");
        String htmlBody = "Templated Html Body <script>nefarious scripting</script>";
        String sanitizedHtmlBody = "Templated Html Body";

        EmailTemplate emailTemplate = new EmailTemplate(from, replyTo, priority, to, cc, bcc, subjectTemplate, textBodyTemplate,
                htmlBodyTemplate);

        XContentBuilder builder = XContentFactory.jsonBuilder();
        emailTemplate.toXContent(builder, ToXContent.EMPTY_PARAMS);

        XContentParser parser = createParser(builder);
        parser.nextToken();

        EmailTemplate.Parser emailTemplateParser = new EmailTemplate.Parser();

        String currentFieldName = null;
        XContentParser.Token token;
        while ((token = parser.nextToken()) != XContentParser.Token.END_OBJECT) {
            if (token == XContentParser.Token.FIELD_NAME) {
                currentFieldName = parser.currentName();
            } else  {
                assertThat(emailTemplateParser.handle(currentFieldName, parser), is(true));
            }
        }
        EmailTemplate parsedEmailTemplate = emailTemplateParser.parsedTemplate();

        Map<String, Object> model = new HashMap<>();

        HtmlSanitizer htmlSanitizer = mock(HtmlSanitizer.class);
        when(htmlSanitizer.sanitize(htmlBody)).thenReturn(sanitizedHtmlBody);

        Email.Builder emailBuilder = parsedEmailTemplate.render(new MockTextTemplateEngine(), model, htmlSanitizer, new HashMap<>());

        assertThat(emailTemplate.from, equalTo(parsedEmailTemplate.from));
        assertThat(emailTemplate.replyTo, equalTo(parsedEmailTemplate.replyTo));
        assertThat(emailTemplate.priority, equalTo(parsedEmailTemplate.priority));
        assertThat(emailTemplate.to, equalTo(parsedEmailTemplate.to));
        assertThat(emailTemplate.cc, equalTo(parsedEmailTemplate.cc));
        assertThat(emailTemplate.bcc, equalTo(parsedEmailTemplate.bcc));
        assertThat(emailTemplate.subject, equalTo(parsedEmailTemplate.subject));
        assertThat(emailTemplate.textBody, equalTo(parsedEmailTemplate.textBody));
        assertThat(emailTemplate.htmlBody, equalTo(parsedEmailTemplate.htmlBody));

        emailBuilder.id("_id");
        Email email = emailBuilder.build();
        assertThat(email.subject, equalTo(subjectTemplate.getTemplate()));
        assertThat(email.textBody, equalTo(textBodyTemplate.getTemplate()));
        assertThat(email.htmlBody, equalTo(sanitizedHtmlBody));
    }

    public void testParsingMultipleEmailAddresses() throws Exception {
        EmailTemplate template = EmailTemplate.builder()
                .from("sender@example.org")
                .to("to1@example.org, to2@example.org")
                .cc("cc1@example.org, cc2@example.org")
                .bcc("bcc1@example.org, bcc2@example.org")
                .textBody("blah")
                .build();

        Email email = template.render(new MockTextTemplateEngine(), emptyMap(), null, emptyMap()).id("foo").build();

        assertThat(email.to.size(), is(2));
        assertThat(email.to, containsInAnyOrder(new Email.Address("to1@example.org"),
                new Email.Address("to2@example.org")));
        assertThat(email.cc.size(), is(2));
        assertThat(email.cc, containsInAnyOrder(new Email.Address("cc1@example.org"),
                new Email.Address("cc2@example.org")));
        assertThat(email.bcc.size(), is(2));
        assertThat(email.bcc, containsInAnyOrder(new Email.Address("bcc1@example.org"),
                new Email.Address("bcc2@example.org")));
    }
}
