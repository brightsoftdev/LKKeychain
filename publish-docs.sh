#!/bin/bash
#
#  publish-docs.sh
#  Generates reference docs and uploads them to GitHub.
#
#  Created by Károly Lőrentey on 2011-10-24.
#  Copyright © 2011, Károly Lőrentey. All rights reserved.
#

set -e

cd "$(dirname "$0")"
echo "Building documentation target..."
xcodebuild -target "Documentation" >/dev/null

PAGES=GitHub-pages
if [ ! -d "$PAGES" ]; then
    echo "Cloning gh-pages branch from GitHub..."
    git clone --quiet --branch gh-pages git@github.com:lorentey/LKKeychain.git "$PAGES"
    cd "$PAGES"
else
    cd "$PAGES"
    if [ $(git status --porcelain | wc -l) '>' 0 ]; then
	echo "$PAGES has uncommitted changes" >&2
	exit 1
    fi
    echo "Pulling latest gh-pages changes from GitHub..."
    git pull --quiet origin
fi


echo "Copying HTML reference..."
git rm -qr reference
mkdir reference
cp -R ../docs/html/* reference
git add reference

if [ $(git status --porcelain | wc -l) '>' 0 ]; then
    echo "Copying DocSet..."
    cp -r ../docs/publish/* downloads
    git add downloads
    
    echo "Committing changes..."
    git commit -m "Regenerate API reference."
    echo "Pushing gh-changes to GitHub..."
    git push origin
else
    echo "No changes"
fi
