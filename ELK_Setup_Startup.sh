#!/bin/bash



# Pulling Elasticsearch and Kibana images

docker pull docker.elastic.co/elasticsearch/elasticsearch:8.12.1

docker pull docker.elastic.co/kibana/kibana:8.12.1



# Creating docker network

docker network create elastic



# Check if containers already exist

if docker ps -a | grep -q -E 'es01|kib01'; then

    echo "Containers already exist. Starting existing containers..."

    docker start kib01 es01

else

    # Creating docker containers

    docker run --name kib01 --net elastic -p 5601:5601 -d docker.elastic.co/kibana/kibana:8.12.1

    docker run --name es01 --net elastic -p 9200:9200 -m 1GB -d docker.elastic.co/elasticsearch/elasticsearch:8.12.1

    echo "Waiting for containers to come up"

    sleep 30



    password=$(docker exec -i es01 /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic <<< "y" 2>/dev/null | grep 'New value:' | awk '{print $NF}')

    # Creating an enrollment token and capturing it directly into a variable

    enrollment_token=$(docker exec -i es01 /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)

    kibana_code=$(docker exec -i kib01 /usr/share/kibana/bin/kibana-verification-code)



    # Outputting information

    echo "Go to http://localhost:5601. Put the enrollment token listed below in the provided box and continue. Your username is Elastic, and password as listed below"

    echo -e "This is your autogenerated password (Change Soon):\n$password"

    echo -e "This is your enrollment token:\n$enrollment_token"

    echo -e "$kibana_code"

fi



