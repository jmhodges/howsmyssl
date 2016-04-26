#!/bin/bash

function die() {
  echo $1 > /dev/stderr
  exit 1
}

if [ -z "${TRAVIS_BRANCH}" ]; then
  die "not running in travis"
fi

if [[ "${TRAVIS_BRANCH}" != "master" && ! "${TRAVIS_BRANCH}" =~ ^test_gcloud_deploy.* ]]; then
  echo "not on master, so no docker work needed"
  exit
fi

if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then
  # TRAVIS_BRANCH is set to master on pull requests, so check if we're
  # in a pull request.
  echo "in a pull request, so no docker work needed"
  exit
fi

function auth_gcloud() {
  if [ ! -d ${HOME}/google-cloud-sdk/bin ]; then
    # If there's no cache, TravisCI will put an empty directory there, which
    # gcloud's install script errors out on. So, delete it and do the download
    rm -rf ${HOME}/google-cloud-sdk
    export CLOUDSDK_CORE_DISABLE_PROMPTS=1
    curl https://sdk.cloud.google.com | bash || die "unable to install gcloud"
    cd -
  fi
  openssl aes-256-cbc -K $encrypted_46319ee087e0_key -iv $encrypted_46319ee087e0_iv -in howsmyssl-gcloud-credentials.json.enc -out ./howsmyssl-gcloud-credentials.json -d || die "unable to decrypt gcloud creds"
  gcloud auth activate-service-account --key-file howsmyssl-gcloud-credentials.json || die "unable to authenticate gcloud service account"
  gcloud components update || die "unable to update all components"
  # This is for when we're on the first install of gcloud.
  gcloud components update kubectl || die "unable to install kubectl"

  gcloud config set container/cluster howsmyssl-4cpu
  gcloud config set compute/zone us-east1-c
  gcloud config set project clever-passage-126802
  gcloud container clusters get-credentials howsmyssl-4cpu || die "unable to get credentials for GKE cluster"
}

export PATH=${HOME}/google-cloud-sdk/bin:$PATH

auth_gcloud &

AUTH_PID=$!

docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS || die "unable to login"

REPO=jmhodges/howsmyssl

# DEPLOY_IMAGE is usually something like jmhodges/howsmyssl:master-48 unless running on a
# test_gcloud_deploy branch
DEPLOY_IMAGE="$REPO:${TRAVIS_BRANCH}-${TRAVIS_BUILD_NUMBER}"

docker build -f Dockerfile -t $REPO .
docker tag -f $REPO:$COMMIT $REPO:latest || die "unable to tag as latest"
docker tag -f $REPO:$COMMIT ${DEPLOY_IMAGE} || die "unable to tag as ${DEPLOY_IMAGE}"

docker push $REPO || die "unable to push docker tags"

wait $AUTH_PID || die "unable to auth_gcloud"

# all the escapes are to get access to ${DEPLOY_IMAGE} inside the string
PATCH="[{\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/image\", \"value\": \"${DEPLOY_IMAGE}\"}]"

# quotes around PATCH are important since there are spaces in it.
kubectl patch deployment frontend-deployment --type="json" -p "${PATCH}" || die "unable to deploy new image"
