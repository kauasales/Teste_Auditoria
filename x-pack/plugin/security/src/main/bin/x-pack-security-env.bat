rem Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
rem or more contributor license agreements. Licensed under the Elastic License;
rem you may not use this file except in compliance with the Elastic License.

call "%~dp0x-pack-env.bat" || exit /b 1

set ES_CLASSPATH=!ES_CLASSPATH!;!ES_HOME!/modules/x-pack/x-pack-security/*
