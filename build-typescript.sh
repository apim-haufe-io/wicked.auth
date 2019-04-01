#!/bin/sh

set -e

./node_modules/typescript/bin/tsc

rm -rf ./dist/views
cp -rf ./src/views ./dist
cp -f package.json ./dist
rm -rf ./dist/assets
mkdir -p ./dist/assets/jquery
mkdir -p ./dist/assets/bootstrap
cp -rf ./node_modules/bootstrap/dist ./dist/assets/bootstrap
cp -rf ./node_modules/jquery/dist ./dist/assets/jquery

node dist/tools/check-translations.js
