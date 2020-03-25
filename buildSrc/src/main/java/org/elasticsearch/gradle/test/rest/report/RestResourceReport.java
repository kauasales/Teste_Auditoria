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
package org.elasticsearch.gradle.test.rest.report;

import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.logging.Logger;
import org.gradle.api.reporting.internal.TaskGeneratedSingleFileReport;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;

import javax.inject.Inject;
import java.io.File;

/**
 * Parent class for any rest resource report. Projects are the gradle path that used to find the rest resources. By default subprojects
 * should also be included in the results. Excludes are ant style globs that should be applied prior to creating the report output.
 */
public abstract class RestResourceReport extends TaskGeneratedSingleFileReport {

    @Inject
    public RestResourceReport(String name, Task task) {
        super(name, task);
    }

    @Input
    public abstract void projects(String... paths);

    @OutputFile
    @Override
    public void setDestination(File file) {
        super.setDestination(file);
    }

    @Input
    public abstract void excludes(String... excludes);

    abstract void appendToReport(Project project, Logger logger);
}
