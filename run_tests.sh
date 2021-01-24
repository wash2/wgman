#!/bin/bash
while read -r line; do export  "$line"; done < "./testenv.list"

../wgman-migration/deploy-postgres
export WGMAN_DB_HOST="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $WGMAN_DB_CONTAINER_NAME)"
cargo run --bin wgman-migration

cargo test
