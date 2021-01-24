#!/bin/bash

while read -r line; do export  "$line"; done < "../env.list"
docker stop $WGMAN_API_CONTAINER_NAME ;
docker rm $WGMAN_API_CONTAINER_NAME ;
docker build --build-arg DATABASE_URL_ARG=$DATABASE_URL -t rust-debian -f ./Dockerfile . && \
    docker run --name $WGMAN_API_CONTAINER_NAME --env-file ../env.list -p $WGMAN_API_PORT:$WGMAN_API_PORT rust-debian &
