#!/bin/bash

source .env
docker-compose -f nts-ng-docker-image-build-ubuntu.yaml build --build-arg NTS_BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg NTS_BUILD_VERSION=$NTS_BUILD_VERSION
