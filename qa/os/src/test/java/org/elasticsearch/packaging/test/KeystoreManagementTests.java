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

package org.elasticsearch.packaging.test;

import org.elasticsearch.packaging.util.Distribution;
import org.elasticsearch.packaging.util.Docker;
import org.elasticsearch.packaging.util.FileUtils;
import org.elasticsearch.packaging.util.Installation;
import org.elasticsearch.packaging.util.Platforms;
import org.elasticsearch.packaging.util.ServerUtils;
import org.elasticsearch.packaging.util.Shell;
import org.junit.Ignore;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import static org.elasticsearch.packaging.util.Archives.ARCHIVE_OWNER;
import static org.elasticsearch.packaging.util.Archives.installArchive;
import static org.elasticsearch.packaging.util.Archives.verifyArchiveInstallation;
import static org.elasticsearch.packaging.util.Docker.assertPermissionsAndOwnership;
import static org.elasticsearch.packaging.util.Docker.waitForPathToExist;
import static org.elasticsearch.packaging.util.FileMatcher.Fileness.File;
import static org.elasticsearch.packaging.util.FileMatcher.file;
import static org.elasticsearch.packaging.util.FileMatcher.p660;
import static org.elasticsearch.packaging.util.FileUtils.rm;
import static org.elasticsearch.packaging.util.Packages.assertInstalled;
import static org.elasticsearch.packaging.util.Packages.assertRemoved;
import static org.elasticsearch.packaging.util.Packages.installPackage;
import static org.elasticsearch.packaging.util.Packages.verifyPackageInstallation;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assume.assumeThat;
import static org.junit.Assume.assumeTrue;

public class KeystoreManagementTests extends PackagingTestCase {

    private static final String PASSWORD_ERROR_MESSAGE = "Provided keystore password was incorrect";

    /** Test initial archive state */
    public void test10InstallArchiveDistribution() throws Exception {
        assumeTrue(distribution().isArchive());

        installation = installArchive(sh, distribution);
        verifyArchiveInstallation(installation, distribution());

        final Installation.Executables bin = installation.executables();
        Shell.Result r = sh.runIgnoreExitCode(bin.keystoreTool.toString() + " has-passwd");
        assertFalse("has-passwd should fail", r.isSuccess());
        assertThat("has-passwd should indicate missing keystore",
            r.stderr, containsString("ERROR: Elasticsearch keystore not found"));
    }

    /** Test initial package state */
    public void test11InstallPackageDistribution() throws Exception {
        assumeTrue(distribution().isPackage());

        assertRemoved(distribution);
        installation = installPackage(sh, distribution);
        assertInstalled(distribution);
        verifyPackageInstallation(installation, distribution, sh);

        final Installation.Executables bin = installation.executables();
        Shell.Result r = sh.runIgnoreExitCode(bin.keystoreTool.toString() + " has-passwd");
        assertFalse("has-passwd should fail", r.isSuccess());
        assertThat("has-passwd should indicate unprotected keystore",
            r.stderr, containsString("ERROR: Keystore is not password-protected"));
        Shell.Result r2 = bin.keystoreTool.run("list");
        assertThat(r2.stdout, containsString("keystore.seed"));
    }

    /** Test initial Docker state */
    public void test12InstallDockerDistribution() throws Exception {
        assumeTrue(distribution().isDocker());

        installation = Docker.runContainer(distribution());

        try {
            waitForPathToExist(installation.config("elasticsearch.keystore"));
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        final Installation.Executables bin = installation.executables();
        Shell.Result r = sh.runIgnoreExitCode(bin.keystoreTool.toString() + " has-passwd");
        assertFalse("has-passwd should fail", r.isSuccess());
        assertThat("has-passwd should indicate unprotected keystore",
            r.stdout, containsString("ERROR: Keystore is not password-protected"));
        Shell.Result r2 = bin.keystoreTool.run("list");
        assertThat(r2.stdout, containsString("keystore.seed"));
    }

    public void test20CreateKeystoreManually() throws Exception {
        rmKeystoreIfExists();
        createKeystore();

        final Installation.Executables bin = installation.executables();
        verifyKeystorePermissions();

        Shell.Result r = bin.keystoreTool.run("list");
        assertThat(r.stdout, containsString("keystore.seed"));
    }

    public void test30AutoCreateKeystore() throws Exception {
        assumeTrue("Packages and docker are installed with a keystore file", distribution.isArchive());
        rmKeystoreIfExists();

        startElasticsearch();
        stopElasticsearch();

        Platforms.onWindows(() -> sh.chown(installation.config("elasticsearch.keystore")));

        verifyKeystorePermissions();

        final Installation.Executables bin = installation.executables();
        Shell.Result r = bin.keystoreTool.run("list");
        assertThat(r.stdout, containsString("keystore.seed"));
    }

    public void test40KeystorePasswordOnStandardInput() throws Exception {
        assumeTrue("packages will use systemd, which doesn't handle stdin",
            distribution.isArchive());
        assumeThat(installation, is(notNullValue()));

        String password = "^|<>\\&exit"; // code insertion on Windows if special characters are not escaped

        rmKeystoreIfExists();
        createKeystore();
        setKeystorePassword(password);

        assertPasswordProtectedKeystore();

        awaitElasticsearchStartup(startElasticsearchStandardInputPassword(password));
        ServerUtils.runElasticsearchTests();
        stopElasticsearch();
    }

    public void test41WrongKeystorePasswordOnStandardInput() {
        assumeTrue("packages will use systemd, which doesn't handle stdin",
            distribution.isArchive());
        assumeThat(installation, is(notNullValue()));

        assertPasswordProtectedKeystore();

        Shell.Result result = startElasticsearchStandardInputPassword("wrong");
        assertElasticsearchFailure(result, PASSWORD_ERROR_MESSAGE);
    }

    @Ignore /* Ignored for feature branch, awaits fix: https://github.com/elastic/elasticsearch/issues/49340 */
    public void test42KeystorePasswordOnTty() throws Exception {
        assumeTrue("expect command isn't on Windows",
            distribution.platform != Distribution.Platform.WINDOWS);
        assumeTrue("packages will use systemd, which doesn't handle stdin",
            distribution.isArchive());
        assumeThat(installation, is(notNullValue()));

        String password = "keystorepass";

        rmKeystoreIfExists();
        createKeystore();
        setKeystorePassword(password);

        assertPasswordProtectedKeystore();

        awaitElasticsearchStartup(startElasticsearchTtyPassword(password));
        ServerUtils.runElasticsearchTests();
        stopElasticsearch();
    }

    @Ignore /* Ignored for feature branch, awaits fix: https://github.com/elastic/elasticsearch/issues/49340 */
    public void test43WrongKeystorePasswordOnTty() throws Exception {
        assumeTrue("expect command isn't on Windows",
            distribution.platform != Distribution.Platform.WINDOWS);
        assumeTrue("packages will use systemd, which doesn't handle stdin",
            distribution.isArchive());
        assumeThat(installation, is(notNullValue()));

        assertPasswordProtectedKeystore();

        Shell.Result result = startElasticsearchTtyPassword("wrong");
        // error will be on stdout for "expect"
        assertThat(result.stdout, containsString(PASSWORD_ERROR_MESSAGE));
    }

    public void test50KeystorePasswordFromFile() throws Exception {
        assumeTrue("only for systemd", Platforms.isSystemd() && distribution().isPackage());
        String password = "!@#$%^&*()|\\<>/?";
        Path esKeystorePassphraseFile = installation.config.resolve("eks");

        rmKeystoreIfExists();
        createKeystore();
        setKeystorePassword(password);

        assertPasswordProtectedKeystore();

        try {
            sh.run("sudo systemctl set-environment ES_KEYSTORE_PASSPHRASE_FILE=" + esKeystorePassphraseFile);

            Files.createFile(esKeystorePassphraseFile);
            Files.write(esKeystorePassphraseFile,
                (password + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.WRITE);

            startElasticsearch();
            ServerUtils.runElasticsearchTests();
            stopElasticsearch();
        } finally {
            sh.run("sudo systemctl unset-environment ES_KEYSTORE_PASSPHRASE_FILE");
        }
    }

    public void test51WrongKeystorePasswordFromFile() throws Exception {
        assumeTrue("only for systemd", Platforms.isSystemd() && distribution().isPackage());
        Path esKeystorePassphraseFile = installation.config.resolve("eks");

        assertPasswordProtectedKeystore();

        try {
            sh.run("sudo systemctl set-environment ES_KEYSTORE_PASSPHRASE_FILE=" + esKeystorePassphraseFile);

            if (Files.exists(esKeystorePassphraseFile)) {
                rm(esKeystorePassphraseFile);
            }

            Files.createFile(esKeystorePassphraseFile);
            Files.write(esKeystorePassphraseFile,
                ("wrongpassword" + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.WRITE);

            Shell.Result result = runElasticsearchStartCommand();
            assertElasticsearchFailure(result, PASSWORD_ERROR_MESSAGE);
        } finally {
            sh.run("sudo systemctl unset-environment ES_KEYSTORE_PASSPHRASE_FILE");
        }
    }

    private void createKeystore() throws Exception {
        Path keystore = installation.config("elasticsearch.keystore");
        final Installation.Executables bin = installation.executables();
        bin.keystoreTool.run("create");

        // this is a hack around the fact that we can't run a command in the same session as the same user but not as administrator.
        // the keystore ends up being owned by the Administrators group, so we manually set it to be owned by the vagrant user here.
        // from the server's perspective the permissions aren't really different, this is just to reflect what we'd expect in the tests.
        // when we run these commands as a role user we won't have to do this
        Platforms.onWindows(() -> {
            sh.chown(keystore);
        });

        if (distribution().isDocker()) {
            try {
                waitForPathToExist(keystore);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void rmKeystoreIfExists() {
        Path keystore = installation.config("elasticsearch.keystore");
        if (distribution().isDocker()) {
            try {
                waitForPathToExist(keystore);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }

            // Move the auto-created one out of the way, or else the CLI prompts asks us to confirm
            sh.run("rm " + keystore);
        } else {
            if (Files.exists(keystore)) {
                FileUtils.rm(keystore);
            }
        }
    }

    private void setKeystorePassword(String password) throws Exception {
        final Installation.Executables bin = installation.executables();

        // set the password by passing it to stdin twice
        Platforms.onLinux(() -> {
            bin.keystoreTool.run("passwd", password + "\n" + password + "\n");
        });

        Platforms.onWindows(() -> {
            sh.run("Invoke-Command -ScriptBlock {echo \'" + password + "\'; echo \'" + password + "\'} | "
                + bin.keystoreTool + " passwd");
        });
    }

    private void assertPasswordProtectedKeystore() {
        Shell.Result r = installation.executables().keystoreTool.run("has-passwd");
        assertThat("keystore should be password protected", r.exitCode, is(0));
    }

    private void verifyKeystorePermissions() {
        Path keystore = installation.config("elasticsearch.keystore");
        switch (distribution.packaging) {
            case TAR:
            case ZIP:
                assertThat(keystore, file(File, ARCHIVE_OWNER, ARCHIVE_OWNER, p660));
                break;
            case DEB:
            case RPM:
                assertThat(keystore, file(File, "root", "elasticsearch", p660));
                break;
            case DOCKER:
                assertPermissionsAndOwnership(keystore, p660);
                break;
            default:
                throw new IllegalStateException("Unknown Elasticsearch packaging type.");
        }
    }
}
