#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK
import os
import sys
import argparse
import shutil
import re
import json
import base64
import subprocess
import tempfile

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="cmd")
setupCmd = subparsers.add_parser("setupServer")
setupCmd.add_argument("--server", required=True)
setupCmd.add_argument("--serverSudoUsername", default="ubuntu")
setupCmd.add_argument("--username", default="reversessh")
setupCmd.add_argument("--port", type=int, required=True)
createConfCmd = subparsers.add_parser("createConf")
createConfCmd.add_argument("--server", required=True)
createConfCmd.add_argument("--serverSudoUsername", default="ubuntu")
createConfCmd.add_argument("--username", default="reversessh")
createConfCmd.add_argument("--port", type=int, required=True)
createConfCmd.add_argument("--output", default="reversessh.conf")
testIncomingCmd = subparsers.add_parser("testIncoming")
testIncomingCmd.add_argument("--conf", default="reversessh.conf")
testIncomingCmd.add_argument("--portRemote", type=int, default=2000)
args = parser.parse_args()


def runRemoteScript(name, *pargs, **kwargs):
    filename = os.path.join(os.path.dirname(__file__), "remotescripts", "%s.py" % name)
    encoded = base64.b64encode(open(filename, "rb").read()).decode()
    arguments = " ".join(["'%s'" % a for a in pargs] + ["'--%s=%s'" % (k, v) for k, v in kwargs.items()])
    return subprocess.check_output(["ssh", "%s@%s" % (args.serverSudoUsername, args.server),
        "echo %s | base64 -d | python3 - %s" % (encoded, arguments)]).decode()


def sshKeygen():
    hostsFile = tempfile.mktemp()
    subprocess.check_call(["ssh-keygen", '-N', '', '-t', 'rsa', '-b', '4096', '-f', hostsFile])
    try:
        with open(hostsFile) as f:
            private = f.read()
        with open(hostsFile + ".pub") as f:
            public = f.read()
        return dict(public=public, private=private)
    finally:
        os.unlink(hostsFile)


if args.cmd == "setupServer":
    print(runRemoteScript("installserver", "setupHere",
            sudoUsername=args.serverSudoUsername, username=args.username, port=args.port))
elif args.cmd == "createConf":
    if os.path.exists(args.output):
        raise Exception("Will not override output file")
    keys = sshKeygen()
    response = runRemoteScript("installsshkey", username=args.username,
        publicBase64=base64.b64encode(keys['public'].encode()).decode())
    print(response)
    serverKey = response.split("SERVER KEY START")[1].split("SERVER KEY END")[0].strip()
    with open(args.output, "w", 0o600) as f:
        f.write(json.dumps(dict(
            key=keys['private'],
            server=args.server,
            serverKey=serverKey,
            port=args.port,
            username=args.username,
        ), indent=4))
    print("Written %s" % args.output)
elif args.cmd == "testIncoming":
    with open(args.conf) as f:
        conf = json.load(f)
    hostsFile = tempfile.NamedTemporaryFile(mode="w")
    hostsFile.write("[%s]:%d %s\n" % (conf['server'], conf['port'], conf['serverKey']))
    hostsFile.flush()
    privateKeyFile = tempfile.NamedTemporaryFile(mode="w", dir="/dev/shm")
    os.fchmod(privateKeyFile.fileno(), 0o600)
    privateKeyFile.write(conf['key'])
    privateKeyFile.flush()
    subprocess.check_call(["ssh",
        "-p", str(conf['port']),
        "-i", privateKeyFile.name,
        "%s@%s" % (conf['username'], conf['server']),
        "-o", "TCPKeepAlive=yes", "-o", "ServerAliveInterval=5",
        "-o", "GlobalKnownHostsFile=%s" % hostsFile.name,
        "-R", "%d:localhost:22" % args.portRemote])
else:
    raise AssertionError("Unknown command: %s" % args.cmd)
