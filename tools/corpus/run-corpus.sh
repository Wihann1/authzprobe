#!/usr/bin/env bash
#
# Runs AuthzProbe against the stock ASP.NET Core templates.
#
# Unit tests prove the rules behave on endpoints we wrote. This proves they behave on
# applications we did not: Microsoft's own templates, generated fresh, with no source
# modification of any kind. The probe attaches through ASPNETCORE_HOSTINGSTARTUPASSEMBLIES.
#
# The templates consume AuthzProbe as a package from a local feed rather than as a project
# reference. That is deliberate twice over: it is what a user actually installs, so packaging
# mistakes surface here; and an SDK cannot evaluate a project multi-targeting a framework it
# does not know, so a .NET 8 corpus run could not reference the project at all.
#
# Usage: tools/corpus/run-corpus.sh [--framework net10.0|net8.0] [--keep]

set -euo pipefail

FRAMEWORK="net10.0"
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --framework) FRAMEWORK="$2"; shift 2 ;;
    --keep)      KEEP=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXPECTATIONS="$REPO_ROOT/tools/corpus/expectations.tsv"
PROJECT="$REPO_ROOT/src/AuthzProbe/AuthzProbe.csproj"
WORK="$(mktemp -d)"

cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$PROJECT" | head -1)"

echo "Corpus root: $WORK"
echo "Framework:   $FRAMEWORK"
echo "Package:     AuthzProbe $VERSION"
echo

# Pack from the repository root, where the newest installed SDK is in charge and every
# target framework can be built.
echo "Packing the library into a local feed..."
dotnet pack "$PROJECT" -c Release -o "$WORK/feed" > /dev/null

# The generated applications live under $WORK. Pinning the SDK here is what makes
# `dotnet new` emit a project targeting the framework under test.
case "$FRAMEWORK" in
  net8.0)  SDK_BAND="8.0.100" ;;
  net10.0) SDK_BAND="10.0.100" ;;
  *) echo "unsupported framework: $FRAMEWORK" >&2; exit 2 ;;
esac

cat > "$WORK/global.json" <<JSON
{
  "sdk": {
    "version": "$SDK_BAND",
    "rollForward": "latestFeature"
  }
}
JSON

cat > "$WORK/NuGet.config" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="corpus-local" value="./feed" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
XML

cd "$WORK"

echo "SDK in use for the corpus: $(dotnet --version)"
echo

failures=0
checked=0

while read -r framework name template extra max_analysed want_errors want_warnings want_infos; do
  case "$name" in ''|\#*) continue ;; esac
  case "$framework" in ''|\#*) continue ;; esac
  [ "$framework" = "$FRAMEWORK" ] || continue
  [ "$extra" = "-" ] && extra=""

  app="$WORK/$name"
  printf '=== %s (dotnet new %s %s)\n' "$name" "$template" "$extra"

  # shellcheck disable=SC2086
  dotnet new "$template" -o "$app" $extra --force > /dev/null
  dotnet add "$app" package AuthzProbe --version "$VERSION" > /dev/null

  # The target application's source is never touched. Prove it, so a future change that
  # quietly starts patching the app cannot pass this check.
  if grep -rql "AuthzProbe" "$app" --include="*.cs"; then
    echo "  FAIL: the template's own source mentions AuthzProbe; the corpus must not modify it"
    failures=$((failures + 1))
    continue
  fi

  report="$WORK/$name.report.md"

  set +e
  ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=AuthzProbe \
  AUTHZPROBE_EXIT=1 \
  AUTHZPROBE_REPORT_PATH="$report" \
  dotnet run --project "$app" --no-launch-profile \
    --urls "http://127.0.0.1:0" > "$WORK/$name.stdout" 2>&1
  run_status=$?
  set -e

  if [ ! -f "$report" ]; then
    echo "  FAIL: no report produced (exit $run_status). Output:"
    sed 's/^/    /' "$WORK/$name.stdout" | tail -20
    failures=$((failures + 1))
    continue
  fi

  analysed=$(sed -n 's/^- Endpoints analysed: \*\*\([0-9]*\)\*\*.*/\1/p' "$report")
  errors=$(sed  -n 's/^- Findings: .*(\([0-9]*\) error.*/\1/p' "$report")
  warnings=$(sed -n 's/^- Findings: .*, \([0-9]*\) warning.*/\1/p' "$report")
  infos=$(sed  -n 's/^- Findings: .*, \([0-9]*\) info.*/\1/p' "$report")

  printf '    analysed=%s errors=%s warnings=%s infos=%s (exit %s)\n' \
    "$analysed" "$errors" "$warnings" "$infos" "$run_status"

  ok=1

  if [ "$analysed" -gt "$max_analysed" ]; then
    echo "  FAIL: analysed $analysed endpoints, cap is $max_analysed."
    echo "        A stock template has a handful of endpoints. A number in the hundreds means"
    echo "        static assets are being reported as an authorization surface again."
    ok=0
  fi

  for pair in "errors:$errors:$want_errors" "warnings:$warnings:$want_warnings" "infos:$infos:$want_infos"; do
    label="${pair%%:*}"; rest="${pair#*:}"; got="${rest%%:*}"; want="${rest##*:}"
    if [ "$got" != "$want" ]; then
      echo "  FAIL: $label = $got, expected $want"
      ok=0
    fi
  done

  if [ "$ok" -eq 0 ]; then
    echo "  --- report ---"
    sed 's/^/    /' "$report" | head -25
    failures=$((failures + 1))
  else
    echo "  OK"
  fi

  checked=$((checked + 1))
  echo
done < "$EXPECTATIONS"

if [ "$checked" -eq 0 ]; then
  echo "corpus: no expectations matched framework $FRAMEWORK" >&2
  exit 1
fi

echo "-----------------------------------------"
if [ "$failures" -gt 0 ]; then
  echo "corpus ($FRAMEWORK): $failures of $checked templates did not match expectations"
  echo
  echo "If a template legitimately changed, update tools/corpus/expectations.tsv — but read"
  echo "the report above first and satisfy yourself the new numbers are right."
  exit 1
fi

echo "corpus ($FRAMEWORK): all $checked templates match expectations"
