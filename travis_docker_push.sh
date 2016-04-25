#!/bin/bash

function die() {
  echo $1 > /dev/stderr
  exit 1
}

echo $HOME
echo $(pwd)

if [ -z "${TRAVIS_BRANCH}" ]; then
  die "not running in travis"
fi

if [ "${TRAVIS_BRANCH}" != "master" ]; then
  echo "not on master, so no docker work needed"
  exit
fi

if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then
  # TRAVIS_BRANCH is set to master on pull requests, so check if we're
  # in a pull request.
  echo "in a pull request, so no docker work needed"
  exit
fi

docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS || die "unable to login"

REPO=jmhodges/howsmyssl

docker build -f Dockerfile -t $REPO .
docker tag -f $REPO:$COMMIT $REPO:latest || die "unable to tag as latest"
docker tag -f $REPO:$COMMIT $REPO:master-$TRAVIS_BUILD_NUMBER || die "unable to tag as master-$TRAVIS_BUILD_NUMBER"

docker push $REPO || die "unable to push docker tags"

