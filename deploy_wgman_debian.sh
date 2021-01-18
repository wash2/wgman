while read -r line; do declare  "$line"; done < "./env.list"
sudo docker remove wgman ;
sudo docker build -t rust-debian -f ./debian/Dockerfile .
sudo docker run --name wgman --env-file env.list -p $WGMAN_API_PORT:$WGMAN_API_PORT rust-debian &
