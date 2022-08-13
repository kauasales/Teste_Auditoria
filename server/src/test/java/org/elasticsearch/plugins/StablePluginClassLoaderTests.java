/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.plugins;

import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.PrivilegedOperations;
import org.elasticsearch.test.compiler.InMemoryJavaCompiler;
import org.elasticsearch.test.jar.JarUtils;

import java.io.IOException;
import java.lang.module.Configuration;
import java.lang.module.ModuleFinder;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

/**
 * How do we test a classloader?
 *
 * Prior art:
 * {/@link org.elasticsearch.core.internal.provider.EmbeddedImplClassLoaderTests}
 *   - creates jars for tests
 */
@ESTestCase.WithoutSecurityManager
public class StablePluginClassLoaderTests extends ESTestCase {

    // This test is just to see that there's a jar with a compiled class in it
    // TODO: remove
    public void testJarWithURLClassLoader() throws Exception {

        Path topLevelDir = createTempDir(getTestName());
        Path outerJar = topLevelDir.resolve("my-jar.jar");
        createJar(outerJar, "MyClass");

        // loading it with a URL classloader (just checking the jar, remove
        // this block)
        URL[] urls = new URL[] { outerJar.toUri().toURL() };
        URLClassLoader parent = URLClassLoader.newInstance(urls, StablePluginClassLoaderTests.class.getClassLoader());
        try {
            PrivilegedAction<URLClassLoader> pa = () -> URLClassLoader.newInstance(urls, parent);
            URLClassLoader loader = AccessController.doPrivileged(pa);
            Class<?> c = loader.loadClass("p.MyClass");
            Object instance = c.getConstructor().newInstance();
            assertThat(instance.toString(), equalTo("MyClass"));
        } finally {
            PrivilegedOperations.closeURLClassLoader(parent);
        }
    }

    // lets me look inside the module system classloader to see how it works
    // TODO: remove
    public void testLoadWithModuleLayer() throws Exception {
        Path topLevelDir = createTempDir(getTestName());
        Path jar = topLevelDir.resolve("my-jar.jar");
        createModularJar(jar, "MyClass");

        // load it with a module
        ModuleFinder moduleFinder = ModuleFinder.of(jar);
        ModuleLayer mparent = ModuleLayer.boot();
        Configuration cf = mparent.configuration().resolve(moduleFinder, ModuleFinder.of(), Set.of("p"));
        // we have the module, but how do we load the class?

        PrivilegedAction<ClassLoader> pa =
            () -> ModuleLayer.defineModulesWithOneLoader(cf, List.of(mparent), this.getClass().getClassLoader()).layer().findLoader("p");
        ClassLoader loader = AccessController.doPrivileged(pa);
        Class<?> c = loader.loadClass("p.MyClass");
        assertThat(c, notNullValue());
        Object instance = c.getConstructor().newInstance();
        assertThat("MyClass", equalTo(instance.toString()));

    }

    // We should be able to pass a URI for the jar and load a class from it.
    public void testLoadFromJar() throws Exception {
        Path topLevelDir = createTempDir(getTestName());
        Path jar = topLevelDir.resolve("modular.jar");
        createJar(jar, "MyClass");

        StablePluginClassLoader loader = StablePluginClassLoader.getInstance(
            StablePluginClassLoaderTests.class.getClassLoader(),
            jar
        );

        URL location = loader.findResource("p/MyClass.class");
        assertThat(location, notNullValue());
        Class<?> c = loader.loadClass("p.MyClass");
        assertThat(c, notNullValue());
        Object instance = c.getConstructor().newInstance();
        assertThat(instance.toString(), equalTo("MyClass"));

        // HOW DO WE ASSOCIATE MODULE WITH CLASS?
        assertThat(c.getModule().getName(), equalTo("synthetic"));
    }

    private static void createJar(Path outerJar, String className) throws IOException {
        Map<String, CharSequence> sources = new HashMap<>();
        sources.put("p." + className, String.format(Locale.ENGLISH, """
            package p;
            public class %s {
                @Override
                public String toString() {
                    return "%s";
                }
            }
            """, className, className));
        var classToBytes = InMemoryJavaCompiler.compile(sources);

        Map<String, byte[]> jarEntries = new HashMap<>();
        jarEntries.put("p/" + className + ".class", classToBytes.get("p." + className));
        JarUtils.createJarWithEntries(outerJar, jarEntries);
    }

    private static void createModularJar(Path jar, String className) throws IOException {
        Map<String, CharSequence> sources = new HashMap<>();
        sources.put("p." + className, String.format(Locale.ENGLISH, """
            package p;
            public class %s {
                @Override
                public String toString() {
                    return "%s";
                }
            }
            """, className, className));
        sources.put("module-info", String.format(Locale.ENGLISH, """
            module p {exports p;}
            """));
        var classToBytes = InMemoryJavaCompiler.compile(sources);

        Map<String, byte[]> jarEntries = new HashMap<>();
        jarEntries.put("p/" + className + ".class", classToBytes.get("p." + className));
        jarEntries.put("module-info.class", classToBytes.get("module-info"));
        JarUtils.createJarWithEntries(jar, jarEntries);
    }

    // test that we don't use parent-first delegation (load from package if module has it)
}
