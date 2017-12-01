#!/bin/bash

set -x

PROJECT=johnbelamaric/contacts-app
BINARY=contacts-api
CONTACTS_REGISTRY=${CONTACTS_REGISTRY:-johnbelamaric}

cd api \
&& docker run --rm -v $(pwd):/go/src/github.com/$PROJECT infoblox/buildtool:v6 sh -c \
     "cd /go/src/github.com/$PROJECT \
      && go version \
      && go get -v \
      && go build -v -o $BINARY" \
&& cd .. \
&& docker build -t $CONTACTS_REGISTRY/$BINARY . \
&& docker push $CONTACTS_REGISTRY/$BINARY

