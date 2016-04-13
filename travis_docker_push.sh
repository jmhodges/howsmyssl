#!/bin/bash

function die() {
  echo $1 > /dev/stderr
  exit 1
}

if [ -z "${TRAVIS_BRANCH}" ]; then
  die "not running in travis"
fi

if [ "${TRAVIS_BRANCH}" != "master" ]; then
  echo "not on master, so no docker work needed"
  exit
fi

echo "TRAVIS_BRANCH is ${TRAVIS_BRANCH}"

docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS || die "unable to login"

REPO=jmhodges/howsmyssl

docker tag $REPO:$COMMIT $REPO:latest || die "unable to tag as latest"
docker tag $REPO:$COMMIT $REPO:master-$TRAVIS_BUILD_NUMBER || die "unable to tag as master-$TRAVIS_BUILD_NUMBER"

docker push $REPO || die "unable to push docker tags"
