#!/bin/sh

set -e

if [ -z "$(which tsc)" ]; then
    echo "ERROR: TypeScript must be installed; run"
    echo "  npm install -g typescript"
    echo "Then try again."
    exit 1
fi

tsc 

rm -rf ./dist/views
cp -rf ./src/views ./dist
cp -f package.json ./dist
rm -rf ./dist/assets
mkdir -p ./dist/assets/jquery
mkdir -p ./dist/assets/bootstrap
cp -rf ./node_modules/bootstrap/dist ./dist/assets/bootstrap
cp -rf ./node_modules/jquery/dist ./dist/assets/jquery

node dist/tools/check-translations.js
