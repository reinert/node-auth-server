#!/bin/sh

mkdir -p .keys
ssh-keygen -t rsa -b 2048 -f .keys/jwtRS256.key -N ''
openssl rsa -in .keys/jwtRS256.key -pubout -outform PEM -out .keys/jwtRS256.key.pub
