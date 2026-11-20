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
printf 'preserve push hook\n' > .git/hooks/pre-push
if sh "$installer"; then echo 'Installer bypassed existing pre-push hook' >&2; exit 1; fi
[ "$(cat .git/hooks/pre-push)" = 'preserve push hook' ]
rm .git/hooks/pre-push
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

# Pre-push must verify the exact committed HEAD and propagate interop failures.
cp "$source_dir/.githooks/pre-push" .githooks/pre-push
cat > fake-bin/make <<'EOF_MAKE'
#!/bin/sh
case "$*" in
 verify) exit 0 ;;
 interop) printf 'interop\n' >> "$SOAP_HOOK_CHECK_LOG"; exit "${SOAP_HOOK_CHECK_STATUS:-0}" ;;
 *) exit 12 ;;
esac
EOF_MAKE
chmod +x fake-bin/make
git add .
git -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm fixture
head=$(git rev-parse HEAD)
export SOAP_HOOK_CHECK_LOG="$tmp/.git/check.log"
ref="refs/heads/fixture $head refs/heads/fixture 0000000000000000000000000000000000000000"
printf '%s\n' "$ref" | .githooks/pre-push
[ "$(cat "$SOAP_HOOK_CHECK_LOG")" = interop ]
export SOAP_HOOK_CHECK_STATUS=7
set +e
printf '%s\n' "$ref" | .githooks/pre-push
status=$?
set -e
[ "$status" -eq 7 ]
set +e
printf 'refs/heads/other 1111111111111111111111111111111111111111 refs/heads/other 0000000000000000000000000000000000000000\n' | .githooks/pre-push
status=$?
set -e
[ "$status" -eq 1 ]
printf 'untracked\n' > unexpected.txt
if printf '%s\n' "$ref" | .githooks/pre-push; then echo 'Pre-push accepted untracked work' >&2; exit 1; fi
rm unexpected.txt
printf 'refs/heads/deleted 0000000000000000000000000000000000000000 refs/heads/deleted %s\n' "$head" | .githooks/pre-push
printf 'unstaged\n' >> tracked.txt
if printf '%s\n' "$ref" | .githooks/pre-push; then echo 'Pre-push accepted a different worktree' >&2; exit 1; fi
git add tracked.txt
if printf '%s\n' "$ref" | .githooks/pre-push; then echo 'Pre-push accepted uncommitted staged work' >&2; exit 1; fi
printf 'Pre-push snapshot and interop failure checks passed.\n'
