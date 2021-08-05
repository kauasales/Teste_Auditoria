/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.gradle.test

import org.elasticsearch.gradle.fixtures.AbstractGradleFuncTest
import org.gradle.testkit.runner.TaskOutcome

class GrantTestPermissionPluginFuncTest extends AbstractGradleFuncTest {

    def "configures test tasks"() {
        file("src/test/java/org/acme/SysPropTest.java") << """
            package org.acme;
            
            import static org.junit.Assert.*;
            import org.junit.After;
            import org.junit.Before;
            import org.junit.Test;

            public class SysPropTest {
                @Test
                public void verifySysProps() {
                    assertNotNull(System.getProperty("gradle.dist.lib"));
                    assertNotNull(System.getProperty("gradle.worker.jar"));
                    assertEquals(System.getProperty("tests.gradle"), "true");
                    assertEquals(System.getProperty("tests.task"), ":test");
                }
            }
        """

        given:
        buildFile << """
        plugins {
            id "elasticsearch.test-permissions"
            id "java"
        }
        
        repositories {
            mavenCentral()
        }
        
        dependencies {
            testImplementation "junit:junit:4.13"
        }
        """

        when:
        def result = gradleRunner('test', '-g', "guh1").build()

        then:
        result.task(":test").outcome == TaskOutcome.SUCCESS

        when:
        result = gradleRunner('test', '-g', "guh2").build()
        then:
        result.task(":test").outcome == TaskOutcome.UP_TO_DATE

    }
}