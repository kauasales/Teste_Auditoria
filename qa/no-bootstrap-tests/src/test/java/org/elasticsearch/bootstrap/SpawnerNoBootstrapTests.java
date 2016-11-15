/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.bootstrap;

import org.apache.lucene.util.Constants;
import org.apache.lucene.util.LuceneTestCase;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Create a simple "daemon controller", put it in the right place and check that it runs.
 *
 * Does nothing on Windows, as it's too hard to simulate a native program using a script.
 *
 * Extends LuceneTestCase rather than ESTestCase as ESTestCase installs seccomp, and that
 * prevents the Spawner class doing its job.  Also needs to run in a separate JVM to other
 * tests that extend ESTestCase for the same reason.
 */
public class SpawnerNoBootstrapTests extends LuceneTestCase {

    private static final String CONTROLLER_SOURCE = "#!/bin/bash\n"
            + "\n"
            + "echo I am alive\n"
            + "\n"
            + "read SOMETHING\n";

    public void testControllerSpawn() throws IOException, InterruptedException {
        if (Constants.WINDOWS) {
            // On Windows you cannot directly run a batch file - you have to run cmd.exe with the batch file
            // as an argument and that's out of the remit of the controller daemon process spawner
            return;
        }

        Path esHome = createTempDir().resolve("esHome");
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(Environment.PATH_HOME_SETTING.getKey(), esHome.toString());
        Settings settings = settingsBuilder.build();

        Environment environment = new Environment(settings);

        // This plugin WILL have a controller daemon
        Path plugin = environment.pluginsFile().resolve("test_plugin");
        Files.createDirectories(plugin);
        Path controllerProgram = Spawner.makeSpawnPath(plugin);
        createControllerProgram(controllerProgram);

        // This plugin will NOT have a controller daemon
        Path otherPlugin = environment.pluginsFile().resolve("other_plugin");
        Files.createDirectories(otherPlugin);

        Spawner spawner = new Spawner();
        spawner.spawnNativePluginControllers(environment);

        List<Process> processes = spawner.getProcesses();
        // 1 because there should only be a reference in the list for the plugin that had the controller daemon, not the other plugin
        assertEquals(1, processes.size());
        Process process = processes.get(0);
        try (BufferedReader stdoutReader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line = stdoutReader.readLine();
            assertEquals("I am alive", line);
            spawner.close();
            // Fail if the process doesn't die within 1 second - usually it will be even quicker but it depends on OS scheduling
            assertTrue(process.waitFor(1, TimeUnit.SECONDS));
        }
    }

    private void createControllerProgram(Path outputFile) throws IOException {
        Path outputDir = outputFile.getParent();
        Files.createDirectories(outputDir);
        Files.write(outputFile, CONTROLLER_SOURCE.getBytes(StandardCharsets.UTF_8));
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        perms.add(PosixFilePermission.OTHERS_READ);
        perms.add(PosixFilePermission.OTHERS_EXECUTE);
        Files.setPosixFilePermissions(outputFile, perms);
    }
}
