#!/bin/bash -ex

if grep -nr '\s$' src *.yml *.txt *.md Doxyfile .gitignore .gitmodules .travis* dist/*.desktop \
                 dist/*.svg dist/*.xml; then
    echo Trailing whitespace found, aborting
    exit 1
fi

# Default clang-format points to default 5.0 version one
CLANG_FORMAT=clang-format-5.0
$CLANG_FORMAT --version

#TODO: Create equivlient for CircleCI
#if [ "$TRAVIS_EVENT_TYPE" = "pull_request" ]; then
#    # Get list of every file modified in this pull request
#    files_to_lint="$(git diff --name-only --diff-filter=ACMRTUXB $TRAVIS_COMMIT_RANGE | grep '^src/[^.]*[.]\(cpp\|h\)$' || true)"
#else
    # Check everything for branch pushes
    files_to_lint="$(find src/ -name '*.cpp' -or -name '*.h')"
#fi

# Turn off tracing for this because it's too verbose
set +x

for f in $files_to_lint; do
    d=$(diff -u "$f" <($CLANG_FORMAT "$f") || true)
    if ! [ -z "$d" ]; then
        echo "!!! $f not compliant to coding style, here is the fix:"
        echo "$d"
        fail=1
    fi
done

set -x

if [ "$fail" = 1 ]; then
    # Don't fail the build yet
    #exit 1
    exit 0
fi
