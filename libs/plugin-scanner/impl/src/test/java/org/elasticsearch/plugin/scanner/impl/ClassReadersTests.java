/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.plugin.scanner.impl;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.compiler.InMemoryJavaCompiler;
import org.elasticsearch.test.jar.JarUtils;
import org.hamcrest.Matchers;
import org.objectweb.asm.ClassReader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ClassReadersTests extends ESTestCase {

    public void testSkipModuleInfo() throws IOException {
        final Path tmp = LuceneTestCase.createTempDir();
        final Path dirWithJar = tmp.resolve("jars-dir");
        Files.createDirectories(dirWithJar);
        Path jar = dirWithJar.resolve("api.jar");
        JarUtils.createJarWithEntries(jar, Map.of("module-info.class", InMemoryJavaCompiler.compile("module-info", """
            module p {}
            """)));

        try (Stream<ClassReader> classReaderStream = ClassReaders.ofDirWithJars(dirWithJar.toString())) {
            assertThat(classReaderStream.collect(Collectors.toList()), Matchers.empty());
        }
    }

    public void testStreamFromJar() throws IOException {
        final Path tmp = LuceneTestCase.createTempDir();
        final Path dirWithJar = tmp.resolve("jars-dir");
        Files.createDirectories(dirWithJar);
        Path jar = dirWithJar.resolve("api.jar");
        JarUtils.createJarWithEntries(jar, Map.of("p/A.class", InMemoryJavaCompiler.compile("p.A", """
            package p;
            public class A {}
            """), "p/B.class", InMemoryJavaCompiler.compile("p.B", """
            package p;
            public class B {}
            """)));

        try (Stream<ClassReader> classReaderStream = ClassReaders.ofDirWithJars(dirWithJar.toString())) {

            List<String> collect = classReaderStream.map(cr -> cr.getClassName()).collect(Collectors.toList());
            assertThat(collect, Matchers.containsInAnyOrder("p/A", "p/B"));
        }
    }

    public void testStreamFromDirWithJars() throws IOException {
        final Path tmp = LuceneTestCase.createTempDir();
        final Path dirWithJar = tmp.resolve("jars-dir");
        Files.createDirectories(dirWithJar);

        // System.setProperty("jdk.module.path", dirWithJar.toString());

        Path jar = dirWithJar.resolve("a_b.jar");
        JarUtils.createJarWithEntries(jar, Map.of("p/A.class", InMemoryJavaCompiler.compile("p.A", """
            package p;
            public class A {}
            """), "p/B.class", InMemoryJavaCompiler.compile("p.B", """
            package p;
            public class B {}
            """)));

        Path jar2 = dirWithJar.resolve("c_d.jar");
        JarUtils.createJarWithEntries(jar2, Map.of("p/C.class", InMemoryJavaCompiler.compile("p.C", """
            package p;
            public class C {}
            """), "p/D.class", InMemoryJavaCompiler.compile("p.D", """
            package p;
            public class D {}
            """)));

        // Stream<ClassReader> classReaderStream = ClassReaders.ofModulePath();
        try (Stream<ClassReader> classReaderStream = ClassReaders.ofDirWithJars(dirWithJar.toString())) {

            List<String> collect = classReaderStream.map(cr -> cr.getClassName()).collect(Collectors.toList());
        }
    }

    public void testStreamOfClassPath() throws IOException {
        final Path tmp = LuceneTestCase.createTempDir();
        final Path dirWithJar = tmp.resolve("jars-dir");
        Files.createDirectories(dirWithJar);

        Path jar = dirWithJar.resolve("a_b.jar");
        JarUtils.createJarWithEntries(jar, Map.of("p/A.class", InMemoryJavaCompiler.compile("p.A", """
            package p;
            public class A {}
            """), "p/B.class", InMemoryJavaCompiler.compile("p.B", """
            package p;
            public class B {}
            """)));

        Path jar2 = dirWithJar.resolve("c_d.jar");
        JarUtils.createJarWithEntries(jar2, Map.of("p/C.class", InMemoryJavaCompiler.compile("p.C", """
            package p;
            public class C {}
            """), "p/D.class", InMemoryJavaCompiler.compile("p.D", """
            package p;
            public class D {}
            """)));

        InMemoryJavaCompiler.compile("p.E", """
            package p;
            public class E {}
            """);
        Files.write(tmp.resolve("E.class"), InMemoryJavaCompiler.compile("p.E", """
            package p;
            public class E {}
            """));

        String classPath = Files.walk(tmp).filter(Files::isRegularFile).map(Path::toString).collect(Collectors.joining(":"));
        try (Stream<ClassReader> classReaderStream = ClassReaders.ofClassPath(classPath)) {

            List<String> collect = classReaderStream.map(cr -> cr.getClassName()).collect(Collectors.toList());
            assertThat(collect, Matchers.containsInAnyOrder("p/A", "p/B", "p/C", "p/D", "p/E"));
        }
    }
}
