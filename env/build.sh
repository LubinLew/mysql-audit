#!/bin/bash
set -e
cd `dirname $0`

####################################################################

DOCKER_IMAGE_NAME=mysql-audit-compiler
DOCKER_IMAGE_TAG=latest

####################################################################

if [ -z $1 ] ; then
  DOCKER_NAME=${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}
else
  DOCKER_NAME=$1
fi

docker build -t ${DOCKER_NAME} .
