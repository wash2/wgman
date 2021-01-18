while read -r line; do declare  "$line"; done < "./env.list"

sudo docker --name wgman-postgres run -e POSTGRES_USER=$WGMAN_DB_USER POSTGRES_PASSWORD=$WGMAN_DB_PW POSTGRES_DB=$WGMAN_DB_NAME -p $WGMAN_DB_PORT
echo "postgres IP: $(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' wgman-postgres)"
