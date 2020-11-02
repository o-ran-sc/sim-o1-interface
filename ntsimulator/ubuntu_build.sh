#!/bin/bash

docker-compose -f nts-ng-docker-image-build-ubuntu.yaml build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') 
