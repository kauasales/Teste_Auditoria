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

package org.elasticsearch.cloud.azure.storage;

import com.microsoft.azure.storage.OperationContext;
import com.microsoft.azure.storage.StorageException;
import org.elasticsearch.cloud.azure.blobstore.util.SocketAccess;
import org.elasticsearch.common.blobstore.BlobMetaData;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import com.microsoft.azure.storage.blob.CloudBlobClient;

import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.unit.ByteSizeUnit;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.common.unit.TimeValue;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.FileAlreadyExistsException;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Azure Storage Service interface
 * @see AzureStorageServiceImpl for Azure REST API implementation
 */
public interface AzureStorageService {

    /**
     * Creates a {@code CloudBlobClient} on each invocation using the current client
     * settings. CloudBlobClient is not thread safe and the settings can change,
     * therefore the instance is not cache-able and should only be reused inside a
     * thread for logically coupled ops. The {@code OperationContext} is used to
     * specify the proxy, but a new context is *required* for each call.
     */
    Tuple<CloudBlobClient, Supplier<OperationContext>> client(String clientName);

    /**
     * Updates settings for building clients. Any client cache is cleared. Future
     * client requests will use the new refreshed settings.
     *
     * @param clientsSettings the settings for new clients
     * @return the old settings
     */
    Map<String, AzureStorageSettings> refreshAndClearCache(Map<String, AzureStorageSettings> clientsSettings);

    ByteSizeValue MIN_CHUNK_SIZE = new ByteSizeValue(1, ByteSizeUnit.BYTES);
    ByteSizeValue MAX_CHUNK_SIZE = new ByteSizeValue(64, ByteSizeUnit.MB);

    final class Storage {
        @Deprecated
        public static final String PREFIX = "cloud.azure.storage.";

        @Deprecated
        public static final Setting<Settings> STORAGE_ACCOUNTS = Setting.groupSetting(Storage.PREFIX, Setting.Property.NodeScope);

        /**
         * Azure timeout (defaults to -1 minute)
         * @deprecated We don't want to support global timeout settings anymore
         */
        @Deprecated
        static final Setting<TimeValue> TIMEOUT_SETTING =
            Setting.timeSetting("cloud.azure.storage.timeout", TimeValue.timeValueMinutes(-1), Property.NodeScope, Property.Deprecated);
    }

    boolean doesContainerExist(String account, String container) throws URISyntaxException, StorageException;

    void removeContainer(String account, String container) throws URISyntaxException, StorageException;

    void createContainer(String account, String container) throws URISyntaxException, StorageException;

    void deleteFiles(String account, String container, String path) throws URISyntaxException, StorageException;

    boolean blobExists(String account, String container, String blob) throws URISyntaxException, StorageException;

    void deleteBlob(String account, String container, String blob) throws URISyntaxException, StorageException;

    InputStream getInputStream(String account, String container, String blob) throws URISyntaxException, StorageException, IOException;

    Map<String, BlobMetaData> listBlobsByPrefix(String account, String container, String keyPath, String prefix)
            throws URISyntaxException, StorageException;

    void writeBlob(String account, String container, String blobName, InputStream inputStream, long blobSize)
            throws URISyntaxException, StorageException, FileAlreadyExistsException;

    static InputStream giveSocketPermissionsToStream(InputStream stream) {
        return new InputStream() {
            @Override
            public int read() throws IOException {
                return SocketAccess.doPrivilegedIOException(stream::read);
            }

            @Override
            public int read(byte[] b) throws IOException {
                return SocketAccess.doPrivilegedIOException(() -> stream.read(b));
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                return SocketAccess.doPrivilegedIOException(() -> stream.read(b, off, len));
            }
        };
    }
}
