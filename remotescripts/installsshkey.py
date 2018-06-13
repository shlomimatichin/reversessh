#!/usr/bin/python3
import os
import sys
insertToPath = os.path.join(os.path.dirname(os.path.dirname(__file__)))
os.environ['PYTHONPATH'] = insertToPath + ":" + os.environ.get('PYTHONPATH', '')
sys.path.insert(0, insertToPath)
import argparse
import subprocess
import base64

parser = argparse.ArgumentParser()
parser.add_argument("--username", default="reversessh")
parser.add_argument("--publicBase64", required=True)
args = parser.parse_args()

with open("/tmp/key", "wb") as f:
    f.write(base64.b64decode(args.publicBase64))
subprocess.check_output(['sudo', 'su', '-', args.username, '-c', 'cat /tmp/key >> ~/.ssh/authorized_keys'])
with open("/home/%s/ssh_host_rsa_key.pub" % args.username, "r") as f:
    key = f.read()
print("SERVER KEY START")
print(key)
print("SERVER KEY END")
print("Key installed")
