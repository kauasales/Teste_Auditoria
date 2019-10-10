package org.elasticsearch.gradle.tool;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.gradle.Version;
import org.gradle.api.GradleException;

import java.io.File;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Contains utilities for checking whether Docker is installed, is executable,
 * has a recent enough version, and appears to be functional. The Elasticsearch build
 * requires Docker &gt;= 17.05 as it uses a multi-stage build.
 */
public class DockerUtils {
    /**
     * Defines the possible locations of the Docker CLI. These will be searched in order.
     */
    private static String[] DOCKER_BINARIES = { "/usr/bin/docker", "/usr/local/bin/docker" };

    /**
     * Searches the entries in {@link #DOCKER_BINARIES} for the Docker CLI. This method does
     * not check whether the Docker installation appears usable, see {@link #getDockerAvailability()}
     * instead.
     *
     * @return the path to a CLI, if available.
     */
    public static Optional<String> getDockerPath() {
        // Check if the Docker binary exists
        return List.of(DOCKER_BINARIES)
            .stream()
            .filter(path -> new File(path).exists())
            .findFirst();
    }

    /**
     * Searches for a functional Docker installation, and returns information about the search.
     * @return the results of the search.
     */
    public static DockerAvailability getDockerAvailability() throws Exception {
        String dockerPath = null;
        Result lastResult = null;
        Version version = null;
        boolean isVersionHighEnough = false;

        // Check if the Docker binary exists
        final Optional<String> dockerBinary = getDockerPath();

        if (dockerBinary.isPresent()) {
            dockerPath = dockerBinary.get();

            // Since we use a multi-stage Docker build, check the Docker version since 17.05
            lastResult = runCommand(dockerPath, "version", "--format", "{{.Server.Version}}");

            if (lastResult.isSuccess() == true) {
                version = Version.fromString(lastResult.stdout.trim(), Version.Mode.RELAXED);

                isVersionHighEnough = version.onOrAfter("17.05.0");

                if (isVersionHighEnough == true) {
                    // Check that we can execute a privileged command
                    lastResult = runCommand(dockerPath, "images");
                }
            }
        }

        boolean isAvailable = isVersionHighEnough && lastResult.isSuccess() == true;

        return new DockerAvailability(isAvailable, isVersionHighEnough, dockerPath, version, lastResult);
    }

    /**
     * An immutable class that represents the results of a Docker search from {@link #getDockerAvailability()}}.
     */
    public static class DockerAvailability {
        /**
         * Indicates whether Docker is available and meets the required criteria.
         * True if, and only if, Docker is:
         * <ul>
         *     <li>Installed</li>
         *     <li>Executable</li>
         *     <li>Is at least version 17.05</li>
         *     <li>Can execute a command that requires privileges</li>
         * </ul>
         */
        public final boolean isAvailable;

        /**
         * True if the installed Docker version is &gt;= 17.05
         */
        public final boolean isVersionHighEnough;

        /**
         * The path to the Docker CLI, or null
         */
        public final String path;

        /**
         * The installed Docker version, or null
         */
        public final Version version;

        /**
         * Information about the last command executes while probing Docker, or null.
         */
        public final Result lastCommand;

        public DockerAvailability(boolean isAvailable, boolean isVersionHighEnough, String path, Version version, Result lastCommand) {
            this.isAvailable = isAvailable;
            this.isVersionHighEnough = isVersionHighEnough;
            this.path = path;
            this.version = version;
            this.lastCommand = lastCommand;
        }
    }

    /**
     * Given a list of tasks that requires Docker, check whether Docker is available, otherwise
     * throw an exception.
     * @param tasks the tasks that require Docker
     * @throws GradleException if Docker is not available. The exception message gives the reason.
     */
    public static void assertDockerIsAvailable(List<String> tasks) {
        DockerAvailability availability = null;

        try {
            availability = getDockerAvailability();
        } catch (Exception e) {
            throwDockerRequiredException("Something went wrong while checking Docker's availability", e);
        }

        if (availability.isAvailable == true) {
            return;
        }

        /*
         * There are tasks in the task graph that require Docker.
         * Now we are failing because either the Docker binary does
         * not exist or because execution of a privileged Docker
         * command failed.
         */
        if (availability.path == null) {
            final String message = String.format(
                Locale.ROOT,
                "Docker (checked [%s]) is required to run the following task%s: \n%s",
                String.join(", ", DOCKER_BINARIES),
                tasks.size() > 1 ? "s" : "",
                String.join("\n", tasks));
            throwDockerRequiredException(message);
        }

        if (availability.isVersionHighEnough == false) {
            final String message = String.format(
                Locale.ROOT,
                "building Docker images requires Docker version 17.05+ due to use of multi-stage builds yet was [%s]",
                availability.version);
            throwDockerRequiredException(message);
        }

        // Some other problem, print the error
        final String message = String.format(
            Locale.ROOT,
            "a problem occurred running Docker from [%s] yet it is required to run the following task%s: \n%s\n" +
                "the problem is that Docker exited with exit code [%d] with standard error output [%s]",
            availability.path,
            tasks.size() > 1 ? "s" : "",
            String.join("\n", tasks),
            availability.lastCommand.exitCode,
            availability.lastCommand.stderr.trim());
        throwDockerRequiredException(message);
    }

    private static void throwDockerRequiredException(final String message) {
        throwDockerRequiredException(message, null);
    }

    private static void throwDockerRequiredException(final String message, Exception e) {
        throw new GradleException(
            message + "\nyou can address this by attending to the reported issue, "
                + "removing the offending tasks from being executed, "
                + "or by passing -Dbuild.docker=false", e);
    }

    /**
     * Runs a command and captures the exit code, standard output and standard error.
     * @param args the command and any arguments to execute
     * @return a object that captures the result of running the command. If an exception occurring
     * while running the command, or the process was killed after reaching the 10s timeout,
     * then the exit code will be -1.
     */
    private static Result runCommand(String... args) throws Exception {
        if (args.length == 0) {
            throw new IllegalArgumentException("Cannot execute with no command");
        }

        final ProcessBuilder command = new ProcessBuilder().command(args);
        final Process process = command.start();

        process.waitFor();

        String stdout = IOUtils.toString(process.getInputStream());
        String stderr = IOUtils.toString(process.getErrorStream());

        process.destroy();

        return new Result(process.exitValue(), stdout, stderr);
    }

    /**
     * This class models the result of running a command. It captures the exit code, standard output and standard error.
     */
    private static class Result {
        public final int exitCode;
        public final String stdout;
        public final String stderr;

        Result(int exitCode, String stdout, String stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.stderr = stderr;
        }

        public boolean isSuccess() {
            return exitCode == 0;
        }

        public String toString() {
            return "exitCode = [" + exitCode + "] " + "stdout = [" + stdout.trim() + "] " + "stderr = [" + stderr.trim() + "]";
        }
    }
}
