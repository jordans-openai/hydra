#!/bin/bash

export TEST_DATABASE_MYSQL="mysql://root:secret@$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hydra_test_database_mysql):3444/mysql?parseTime=true&multiStatements=true"
export TEST_DATABASE_POSTGRESQL="postgres://postgres:secret@$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hydra_test_database_postgres):3445/postgres?sslmode=disable"
export TEST_DATABASE_COCKROACHDB="cockroach://root@$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hydra_test_database_cockroach):3446/defaultdb?sslmode=disable"
#export REDIS_URL="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hydra_test_redis):6379"
export REDIS_URL="127.0.0.1:6379"

