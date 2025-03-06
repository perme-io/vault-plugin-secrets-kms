#!/bin/sh

DOCKER_DIR=$(realpath "$(dirname "$0")")
ROOT="${DOCKER_DIR}/.."

NAMESPACE=${NAMESPACE:-parameta-w}
REPO=${REPO:-vault}
TAG=${TAG:-latest}
IMAGE=${NAMESPACE}/${REPO}:${TAG}

echo "Building image ${IMAGE}"
docker build \
    -t ${IMAGE} \
    -f ${DOCKER_DIR}/Dockerfile \
    ${ROOT}
