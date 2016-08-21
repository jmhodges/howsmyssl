#!/bin/bash

function die() {
  echo $1 > /dev/stderr
  exit 1
}

if [ -z "${TRAVIS_BRANCH}" ]; then
  die "not running in travis"
fi

if [[ "${TRAVIS_BRANCH}" == "master" || "${TRAVIS_BRANCH}" =~ ^test_gcloud_deploy.* ]]; then
  DO_DEPLOY=1
elif [[ "${TRAVIS_BRANCH}" =~ test_docker_push.* ]]; then
  # Only do the docker work, but not the gcloud deploy
  DO_DEPLOY=0
else
  echo "not on pushable or deployable branch, so no docker work needed"
  exit
fi

if [ "${TRAVIS_PULL_REQUEST}" != "false" ]; then
  # TRAVIS_BRANCH is set to master on pull requests, so check if we're
  # in a pull request.
  echo "in a pull request, so no docker work needed"
  exit
fi

function auth_gcloud() {
  export CLOUDSDK_CORE_DISABLE_PROMPTS=1
  if [ ! -d ${HOME}/google-cloud-sdk/bin ]; then
    # If there's no cache, TravisCI will put an empty directory there, which
    # gcloud's install script errors out on. So, delete it and do the download
    rm -rf ${HOME}/google-cloud-sdk
    curl https://sdk.cloud.google.com | bash || die "unable to install gcloud"
    cd -
  else
    echo "Skipping gcloud download, using the cache of it"
  fi
  openssl aes-256-cbc -K $encrypted_46319ee087e0_key -iv $encrypted_46319ee087e0_iv -in howsmyssl-gcloud-credentials.json.enc -out ./howsmyssl-gcloud-credentials.json -d || die "unable to decrypt gcloud creds"
  gcloud auth activate-service-account --key-file howsmyssl-gcloud-credentials.json || die "unable to authenticate gcloud service account"
  gcloud components update || die "unable to update all components"
  # This is for when we're on the first install of gcloud.
  gcloud components update kubectl || die "unable to install kubectl"

  gcloud config set container/cluster sites
  gcloud config set compute/zone us-east1-c
  gcloud config set project personal-sites-1295

  gcloud container clusters get-credentials sites || die "unable to get credentials for GKE cluster"
}

export PATH=${HOME}/google-cloud-sdk/bin:$PATH

AUTH_PID=1

if [[ "${DO_DEPLOY}" == "1" ]]; then
  auth_gcloud &

  AUTH_PID=$!
fi

docker login -u $DOCKER_USER -p $DOCKER_PASS || die "unable to login"

REPO=jmhodges/howsmyssl

SHA=$(git rev-parse --short HEAD)

# DEPLOY_IMAGE is usually something like jmhodges/howsmyssl:master-ffffff-48
# unless running on a test_gcloud_deploy branch
DEPLOY_IMAGE="$REPO:${TRAVIS_BUILD_NUMBER}-${TRAVIS_BRANCH}-${SHA}"

docker build -f Dockerfile -t $DEPLOY_IMAGE . || die "unable to build as ${DEPLOY_IMAGE}"

docker push $REPO || die "unable to push docker tags"
echo "Pushed image to docker hub: ${DEPLOY_IMAGE}"

if [[ "${DO_DEPLOY}" != "1" ]]; then
  echo "Finished push. Skipping deploy because of the branch we're on."
  # Don't need any of the rest of this file.
  exit
fi

wait $AUTH_PID || die "unable to auth_gcloud"

# all the escapes are to get access to ${DEPLOY_IMAGE} inside the string
PATCH="[{\"op\": \"replace\", \"path\": \"/spec/template/spec/containers/0/image\", \"value\": \"${DEPLOY_IMAGE}\"}]"

# quotes around PATCH are important since there are spaces in it.
kubectl patch deployment --namespace=prod howsmyssl-deployment --type="json" -p "${PATCH}" || die "unable to deploy new image"
