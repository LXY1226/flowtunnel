import argparse
import json
import pathlib
import subprocess
import sys

from local_e2e import stop_process, wait_ready

parser = argparse.ArgumentParser()
parser.add_argument('--exe', required=True, type=pathlib.Path)
parser.add_argument('--profile', required=True, type=pathlib.Path)
args = parser.parse_args()
log_path = args.profile / 'client-local.log'
with log_path.open('wb') as log:
    client = subprocess.Popen([str(args.exe), 'run', str(args.profile / 'client-local.toml')], stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
    try:
        wait_ready(client, log_path)
        subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('remote_probe.py')), '--results', str(args.profile / 'local-probe.json')], check=True)
        subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('remote_probe.py')), '--udp-only', '--sessions', '4', '--rounds', '20', '--results', str(args.profile / 'local-udp-stress.json')], check=True)
    finally:
        cleanup = stop_process(client, 'client')
        assert cleanup['method'] == 'named_event' and cleanup['exit_code'] == 0, cleanup
