/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.core.internal.provider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.PrivilegedAction;
import java.security.SecureClassLoader;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.Function;

/**
 * A class loader that is responsible for loading implementation classes and resources embedded within an archive.
 *
 * <p> This loader facilitates a scenario whereby an API can embed its implementation and dependencies all within the same archive as the
 * API itself. The archive can be put directly on the class path, where it's API classes are loadable by the application class loader, but
 * the embedded implementation and dependencies are not. When locating a concrete provider, the API can create an instance of an
 * EmbeddedImplClassLoader to locate and load the implementation.
 *
 * <p> The archive typically consists of two disjoint logically groups:
 *  1. the top-level classes and resources,
 *  2. the embedded classes and resources
 *
 * <p> The top-level classes and resources are typically loaded and located, respectively, by the parent of an EmbeddedImplClassLoader
 * loader. The embedded classes and resources, are located by the parent loader as pure resources with a provider specific name prefix, and
 * classes are defined by the EmbeddedImplClassLoader. The list of prefixes is determined by reading the entries in the MANIFEST.TXT.
 *
 * <p> For example, the structure of the archive named x-content:
 * <pre>
 *  /org/elasticsearch/xcontent/XContent.class
 *  /IMPL-JARS/x-content/LISTING.TXT - contains list of jar file names, newline separated
 *  /IMPL-JARS/x-content/x-content-impl.jar/xxx
 *  /IMPL-JARS/x-content/dep-1.jar/abc
 *  /IMPL-JARS/x-content/dep-2.jar/xyz
 * </pre>
 */
public final class EmbeddedImplClassLoader extends SecureClassLoader {

    private final List<String> prefixes;
    private final ClassLoader parent;
    private final Map<String, CodeSource> prefixToCodeBase;

    private static final String IMPL_PREFIX = "IMPL-JARS/";
    private static final String MANIFEST_FILE = "/LISTING.TXT";

    static EmbeddedImplClassLoader getInstance(ClassLoader parent, String providerName) {
        return new EmbeddedImplClassLoader(parent, getProviderPrefixes(parent, providerName));
    }

    private EmbeddedImplClassLoader(ClassLoader parent, Map<String, CodeSource> prefixToCodeBase) {
        super(parent);
        this.prefixes = prefixToCodeBase.keySet().stream().toList();
        this.prefixToCodeBase = prefixToCodeBase;
        this.parent = parent;
    }

    record Resource(InputStream inputStream, CodeSource codeSource) {}

    /** Searches for the named resource. Iterates over all prefixes. */
    private Resource privilegedGetResourceOrNull(String name) {
        return AccessController.doPrivileged(new PrivilegedAction<Resource>() {
            @Override
            public Resource run() {
                for (String prefix : prefixes) {
                    URL url = parent.getResource(prefix + "/" + name);
                    if (url != null) {
                        try {
                            InputStream is = url.openStream();
                            return new Resource(is, prefixToCodeBase.get(prefix));
                        } catch (IOException e) {
                            // silently ignore, same as ClassLoader
                        }
                    }
                }
                return null;
            }
        });
    }

    @Override
    public Class<?> findClass(String moduleName, String name) {
        try {
            Class<?> c = findClass(name);
            if (moduleName != null && moduleName.equals(c.getModule().getName()) == false) {
                throw new AssertionError("expected module:" + moduleName + ", got: " + c.getModule().getName());
            }
            return c;
        } catch (ClassNotFoundException ignore) {}
        return null;
    }

    @Override
    public Class<?> findClass(String name) throws ClassNotFoundException {
        String filepath = name.replace('.', '/').concat(".class");
        Resource res = privilegedGetResourceOrNull(filepath);
        if (res != null) {
            try (InputStream in = res.inputStream()) {
                byte[] bytes = in.readAllBytes();
                return defineClass(name, bytes, 0, bytes.length, res.codeSource());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return super.findClass(name);
    }

    @Override
    protected URL findResource(String name) {
        Objects.requireNonNull(name);
        URL url = prefixes.stream().map(p -> p + "/" + name).map(parent::getResource).filter(Objects::nonNull).findFirst().orElse(null);
        if (url != null) {
            return url;
        }
        return super.findResource(name);
    }

    @Override
    protected Enumeration<URL> findResources(String name) throws IOException {
        final int size = prefixes.size();
        @SuppressWarnings("unchecked")
        Enumeration<URL>[] tmp = (Enumeration<URL>[]) new Enumeration<?>[size + 1];
        for (int i = 0; i < size; i++) {
            tmp[i] = parent.getResources(prefixes.get(i) + "/" + name);
        }
        tmp[size] = super.findResources(name);
        return new CompoundEnumeration<>(tmp);
    }

    /**
     * Returns a module finder capable of finding the modules that are loadable by this embedded impl class loader.
     *
     * <p> The module finder returned by this method can be used during resolution in order to create a configuration. This configuration
     * can subsequently be materialized as a module layer in which classes and resources are loaded by this embedded impl class loader.
     */
    ModuleFinder moduleFinder() throws IOException {
        Path[] modulePath = modulePath();
        assert modulePath.length >= 1;
        ModuleFinder moduleFinder1 = InMemoryModuleFinder.of(modulePath);
        if (modulePath[0].getFileSystem().provider().getScheme().equals("jar")) {
            modulePath[0].getFileSystem().close();
        }
        ModuleFinder moduleFinder2 = InMemoryModuleFinder.of(
            ModuleDescriptor.newModule("jackson-databind").build()  // stub databind
        );
        return ModuleFinder.compose(moduleFinder1, moduleFinder2);
    }

    private Path[] modulePath() throws IOException {
        Function<Path, Path[]> entries = path -> prefixToCodeBase.keySet().stream().map(pfx -> path.resolve(pfx)).toArray(Path[]::new);
        URI rootURI = rootURI(prefixToCodeBase.values().stream().findFirst().map(CodeSource::getLocation).orElseThrow());
        if (rootURI.getScheme().equals("file")) {
            return entries.apply(Path.of(rootURI));
        } else if (rootURI.getScheme().equals("jar")) {
            FileSystem fileSystem = FileSystems.newFileSystem(rootURI, Map.of(), ClassLoader.getSystemClassLoader());
            Path rootPath = fileSystem.getPath("/");
            return entries.apply(rootPath);
        }
        throw new UncheckedIOException(new IOException("unknown scheme:" + rootURI.getScheme()));
    }

    // -- infra

    /**
     * Returns the root URI for a given url. The root URI is the base URI where all classes and resources can be searched for by appending
     * a prefixes.
     *
     * Depending on whether running from a jar (distribution), or an exploded archive (testing), the given url will have one of two schemes,
     * "file", or "jar:file". For example:
     *  distro- jar:file:/xxx/distro/lib/elasticsearch-x-content-8.2.0-SNAPSHOT.jar!/IMPL-JARS/x-content/xlib-2.10.4.jar
     *  test  - file:/x/git/es_modules/libs/x-content/build/generated-resources/impl/IMPL-JARS/x-content/xlib-2.10.4.jar
     */
    private static URI rootURI(URL url) {
        try {
            URI embeddedJarURI = url.toURI();
            if (embeddedJarURI.getScheme().equals("jar")) {
                String s = embeddedJarURI.toString();
                return URI.create(s.substring(0, s.lastIndexOf("!/")));
            } else {
                return URI.create(getParent(getParent(getParent(embeddedJarURI.toString()))));
            }
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private static Map<String, CodeSource> getProviderPrefixes(ClassLoader parent, String providerName) {
        String providerPrefix = IMPL_PREFIX + providerName;
        URL manifest = parent.getResource(providerPrefix + MANIFEST_FILE);
        if (manifest == null) {
            throw new IllegalStateException("missing x-content provider jars list");
        }
        try (
            InputStream in = manifest.openStream();
            InputStreamReader isr = new InputStreamReader(in, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(isr)
        ) {
            List<String> jars = reader.lines().toList();
            Map<String, CodeSource> map = new HashMap<>();
            for (String jar : jars) {
                map.put(providerPrefix + "/" + jar, new CodeSource(new URL(manifest, jar), (CodeSigner[]) null /*signers*/));
            }
            return Collections.unmodifiableMap(map);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String getParent(String uriString) {
        int index = uriString.lastIndexOf('/');
        if (index > 0) {
            return uriString.substring(0, index);
        }
        return "/";
    }

    private static final class CompoundEnumeration<E> implements Enumeration<E> {
        private final Enumeration<E>[] enumerations;
        private int index;

        CompoundEnumeration(Enumeration<E>[] enumerations) {
            this.enumerations = enumerations;
        }

        private boolean next() {
            while (index < enumerations.length) {
                if (enumerations[index] != null && enumerations[index].hasMoreElements()) {
                    return true;
                }
                index++;
            }
            return false;
        }

        public boolean hasMoreElements() {
            return next();
        }

        public E nextElement() {
            if (next() == false) {
                throw new NoSuchElementException();
            }
            return enumerations[index].nextElement();
        }
    }
}
