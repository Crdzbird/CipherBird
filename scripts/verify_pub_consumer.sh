#!/usr/bin/env bash
# Prove cryptolib_flutter works for a pub.dev CONSUMER before publishing.
#
# Builds the exact archive that would be published (git HEAD contents of the
# plugin, symlinks materialised the way pub does, .pubignore applied), serves
# it from a local pub-protocol server, creates a fresh `flutter create` app
# that depends on it as a HOSTED package (not a path dependency — pub's real
# download/extract path is exercised), copies the package's own test suite
# into an integration test, and runs it on the requested device.
#
# Usage: scripts/verify_pub_consumer.sh <flutter device id | macos> [port]
#   scripts/verify_pub_consumer.sh macos
#   scripts/verify_pub_consumer.sh 526C44E8-...   # iOS simulator UDID
#   scripts/verify_pub_consumer.sh 29131FDH3006NV # attached Android device
set -euo pipefail
DEVICE="${1:?device id required (see: flutter devices)}"
PORT="${2:-8765}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN=bridge/bindings/cryptolib_flutter
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cl_pubconsumer.XXXXXX")"
VERSION="$(sed -n 's/^version: //p' "$ROOT/$PLUGIN/pubspec.yaml")"
HOST_KEY="localhost%58$PORT"
echo "══ cryptolib_flutter $VERSION → consumer test on $DEVICE (work dir $WORK)"

# 1. Archive exactly what git HEAD holds for the plugin, symlinks materialised.
mkdir -p "$WORK/stage" "$WORK/pkg" "$WORK/serve"
git -C "$ROOT" archive HEAD "$PLUGIN" | tar -x -C "$WORK/stage"
cp -RL "$WORK/stage/$PLUGIN/." "$WORK/pkg/"
( cd "$WORK/pkg" && grep -vE '^(#|!|$)' .pubignore | xargs rm -rf 2>/dev/null || true
  COPYFILE_DISABLE=1 tar -czf "$WORK/serve/cryptolib_flutter-$VERSION.tar.gz" . )
echo "   archive: $(du -h "$WORK/serve/cryptolib_flutter-$VERSION.tar.gz" | cut -f1)"

# 2. Minimal pub-protocol server (GET /api/packages/<name> + the archive).
cat > "$WORK/pubserver.py" <<PY
import http.server, json, sys, yaml
PORT=$PORT; ROOT="$WORK/serve"; VER="$VERSION"
PUBSPEC=yaml.safe_load(open("$WORK/pkg/pubspec.yaml"))
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self,*a,**k): super().__init__(*a,directory=ROOT,**k)
    def do_GET(self):
        if self.path.startswith('/api/packages/cryptolib_flutter'):
            v={"version":VER,"archive_url":f"http://localhost:{PORT}/cryptolib_flutter-{VER}.tar.gz","pubspec":PUBSPEC}
            body=json.dumps({"name":"cryptolib_flutter","latest":v,"versions":[v]}).encode()
            self.send_response(200); self.send_header('Content-Type','application/vnd.pub.v2+json')
            self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
        super().do_GET()
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(('127.0.0.1',PORT),H).serve_forever()
PY
python3 -c "import yaml" 2>/dev/null || { echo "needs PyYAML: pip3 install pyyaml"; exit 1; }
if lsof -ti:"$PORT" >/dev/null 2>&1; then echo "✗ port $PORT is already in use (pass another port as the 2nd argument)"; exit 1; fi
python3 "$WORK/pubserver.py" & SERVER=$!
trap 'kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null; rm -rf "$HOME/.pub-cache/hosted/$HOST_KEY" "$HOME/.pub-cache/hosted-hashes/$HOST_KEY"' EXIT
sleep 1

# 3. Fresh consumer app depending on the HOSTED package.
( cd "$WORK" && flutter create --platforms=android,ios,macos --org dev.consumer consumer_app >/dev/null )
APP="$WORK/consumer_app"
python3 - "$APP/pubspec.yaml" "$PORT" "$VERSION" <<'PY'
import sys; p,port,ver=sys.argv[1:]; s=open(p).read()
s=s.replace("dependencies:\n  flutter:\n    sdk: flutter\n",f"dependencies:\n  flutter:\n    sdk: flutter\n  cryptolib_flutter:\n    hosted: http://localhost:{port}\n    version: ^{ver}\n",1)
s=s.replace("dev_dependencies:\n  flutter_test:\n    sdk: flutter\n","dev_dependencies:\n  flutter_test:\n    sdk: flutter\n  integration_test:\n    sdk: flutter\n",1)
open(p,'w').write(s)
PY
rm -rf "$HOME/.pub-cache/hosted/$HOST_KEY" "$HOME/.pub-cache/hosted-hashes/$HOST_KEY"
( cd "$APP" && flutter pub get >/dev/null )
CACHED="$HOME/.pub-cache/hosted/$HOST_KEY/cryptolib_flutter-$VERSION"
[[ -f "$CACHED/android/src/main/jniLibs/arm64-v8a/libcryptolib_c.so" ]] || { echo "✗ installed package has no Android binary"; exit 1; }
[[ -d "$CACHED/ios/cryptolib_flutter/CryptoLibC.xcframework" ]] || { echo "✗ installed package has no iOS xcframework"; exit 1; }
echo "   installed from hosted source into $CACHED ($(du -sh "$CACHED" | cut -f1))"

# 4. The package's own test suite, run on the device from the installed copy.
mkdir -p "$APP/integration_test/suites"
cp "$CACHED"/test/*_test.dart "$APP/integration_test/suites/"
python3 - "$APP/integration_test" <<'PY'
import os,sys; d=sys.argv[1]
fs=sorted(f for f in os.listdir(f"{d}/suites") if f.endswith('_test.dart'))
imp="\n".join(f"import 'suites/{f}' as {f[:-5]};" for f in fs)
grp="\n".join(f"  group('{f[:-10]}', {f[:-5]}.main);" for f in fs)
open(f"{d}/all_test.dart","w").write("import 'package:flutter_test/flutter_test.dart';\nimport 'package:integration_test/integration_test.dart';\n"+imp+"\n\nvoid main() {\n  IntegrationTestWidgetsFlutterBinding.ensureInitialized();\n"+grp+"\n}\n")
PY
cd "$APP"
if flutter test integration_test/all_test.dart -d "$DEVICE" 2>&1 | tee "$WORK/test.log" | grep -qE "All tests passed"; then
    echo "✓ consumer test PASSED on $DEVICE ($(grep -oE '\+[0-9]+' "$WORK/test.log" | tail -1 | tr -d +) tests)"
else
    grep -E "\[E\]|error|Error" "$WORK/test.log" | head -20; echo "✗ consumer test FAILED on $DEVICE (log: $WORK/test.log)"; exit 1
fi
