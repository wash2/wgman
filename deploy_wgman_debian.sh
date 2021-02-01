#!/bin/bash

# while read -r line; do export  "$line"; done < "../env.list"
docker stop $WGMAN_API_CONTAINER_NAME ;
docker rm $WGMAN_API_CONTAINER_NAME ;
docker build -t rust-debian -f ./Dockerfile . && \
    docker run --name $WGMAN_API_CONTAINER_NAME --env-file ../env.list --restart always -p $WGMAN_API_PORT:$WGMAN_API_PORT rust-debian &
