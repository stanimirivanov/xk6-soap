#!/bin/sh
set -eu
source_dir=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
cd "$tmp"
git init -q
mkdir -p .githooks fake-bin
cp "$source_dir/.githooks/pre-commit" .githooks/pre-commit
installer="$source_dir/scripts/install-hooks.sh"

git config core.hooksPath custom
if sh "$installer"; then echo 'Installer replaced existing hooksPath' >&2; exit 1; fi
[ "$(git config core.hooksPath)" = custom ]
git config --unset core.hooksPath
printf 'preserve me\n' > .git/hooks/pre-commit
if sh "$installer"; then echo 'Installer bypassed existing hook' >&2; exit 1; fi
[ "$(cat .git/hooks/pre-commit)" = 'preserve me' ]
rm .git/hooks/pre-commit
sh "$installer"
[ "$(git config core.hooksPath)" = .githooks ]

# Substitute only the expensive check runner; exercise real Git index/worktree state.
printf '#!/bin/sh\n[ "$*" = verify ] || exit 12\nexit 0\n' > fake-bin/make
chmod +x fake-bin/make
export PATH="$tmp/fake-bin:$PATH"
printf 'staged\n' > tracked.txt
git add .
printf 'unstaged\n' >> tracked.txt
if .githooks/pre-commit; then echo 'Hook accepted unstaged work' >&2; exit 1; fi
[ "$(tail -n 1 tracked.txt)" = unstaged ]
git add tracked.txt
printf 'untracked\n' > untracked.txt
if .githooks/pre-commit; then echo 'Hook accepted untracked work' >&2; exit 1; fi
[ -f untracked.txt ]
rm untracked.txt
.githooks/pre-commit
printf '#!/bin/sh\nexit 7\n' > fake-bin/make
git add fake-bin/make
set +e
.githooks/pre-commit
status=$?
set -e
[ "$status" -eq 7 ]
printf 'Hook preservation, snapshot, and failure-propagation checks passed.\n'
