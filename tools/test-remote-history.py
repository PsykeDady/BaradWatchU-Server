#!/usr/bin/env python3
"""Real isolated Client + mocked OIDC, with private Server presentation settings."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--client', required=True, type=Path, help='Built Client agent executable')
parser.add_argument('--artifacts', type=Path, help='Optional directory for verified PDFs')
args = parser.parse_args()
client = args.client.resolve(strict=True)
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='bwu-server-history-e2e-') as temp:
    config = Path(temp) / 'config/baradwatchu'
    config.mkdir(parents=True, mode=0o700)
    (config / 'language.json').write_text('{"schemaVersion":"baradwatchu.language.v1","language":"english"}')
    env = dict(os.environ, XDG_CONFIG_HOME=str(config.parent), BWU_CLIENT_BIN=str(client))
    env.pop('BWU_E2E_ARTIFACT_DIR', None)
    if args.artifacts:
        args.artifacts.mkdir(parents=True, exist_ok=True)
        env['BWU_E2E_ARTIFACT_DIR'] = str(args.artifacts.resolve())
    result = subprocess.run([
        'cargo', 'test', '--manifest-path', str(root / 'Cargo.toml'), '--locked', '--offline',
        '--lib', 'e2e_tests::', '--', '--ignored', '--nocapture', '--test-threads=1',
    ], env=env)
    raise SystemExit(result.returncode)
