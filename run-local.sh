#!/bin/bash
set -a
source .env
set +a
./gradlew bootRun

#chmod +x run-local.sh
#./run-local.sh