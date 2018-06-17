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
import time
import logging
import atexit
import signal
import random

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
createConfCmd.add_argument("--comment", required=True)
testIncomingCmd = subparsers.add_parser("testIncoming")
testIncomingCmd.add_argument("--conf", default="reversessh.conf")
testIncomingCmd.add_argument("--portRemote", type=int, default=2000)
setupIncomingServiceCmd = subparsers.add_parser("setupIncomingService")
setupIncomingServiceCmd.add_argument("--conf", required=True)
setupIncomingServiceCmd.add_argument("--portRemote", type=int, required=True)
incomingServiceCmd = subparsers.add_parser("incomingService")
incomingServiceCmd.add_argument("--conf", default="/etc/reversessh.conf")
incomingServiceCmd.add_argument("--deviceRegexWhenNoDefaultRoute")
linkCmd = subparsers.add_parser("link")
linkCmd.add_argument("--conf", default="reversessh.conf")
linkCmd.add_argument("--portRemote", type=int, required=True, nargs="+")
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


def incomingConnection(conf, portRemote):
    route = []
    output = subprocess.check_output(["ip", "route", "show"]).decode()
    if 'default via' in output:
        print("Found default route")
    else:
        if args.deviceRegexWhenNoDefaultRoute:
            options = [line for line in output.split("\n")
                    if re.search("dev " + args.deviceRegexWhenNoDefaultRoute, line) is not None]
            if len(options) > 0:
                line = options[random.randrange(0, len(options))]
                sourceAddress = re.search(r"src (\d+\.\d+\.\d+\.\d+)", line).group(1)
                route = ['-b', sourceAddress]
                print("Attempting to use %s as source address" % sourceAddress)
            else:
                raise Exception("No route and no deviceRegexWhenNoDefaultRoute devices")
        else:
            raise Exception("No route")
    ssh(conf, route + ["-R", "%d:localhost:22" % portRemote])


def outgoingConnection(conf, portRemote):
    extra = []
    for port in portRemote:
        extra += ['-L', '%d:localhost:%d' % (port, port)]
    ssh(conf, extra)


def ssh(conf, additionalCli):
    hostsFile = tempfile.NamedTemporaryFile(mode="w")
    hostsFile.write("[%s]:%d %s\n" % (conf['server'], conf['port'], conf['serverKey']))
    hostsFile.flush()
    privateKeyFile = tempfile.NamedTemporaryFile(mode="w", dir="/dev/shm")
    os.fchmod(privateKeyFile.fileno(), 0o600)
    privateKeyFile.write(conf['key'])
    privateKeyFile.flush()
    child = subprocess.Popen(["ssh",
        '-N',
        "-p", str(conf['port']),
        "-i", privateKeyFile.name,
        "%s@%s" % (conf['username'], conf['server']),
        "-o", "TCPKeepAlive=yes", "-o", "ServerAliveInterval=5",
        "-o", "GlobalKnownHostsFile=%s" % hostsFile.name] +
        additionalCli)
    print("SSH started")
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(10))
    signal.signal(signal.SIGINT, lambda *args: sys.exit(10))
    atexit.register(lambda *args: child.terminate())
    child.wait()


SERVICE_FILE = r'''
[Unit]
Description=ReverseSSH incoming connection
After=network.target auditd.service
ConditionPathExists=!/etc/reverse_ssh_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStart=/usr/bin/python3 /usr/sbin/reversessh.py incomingService
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=simple

[Install]
WantedBy=multi-user.target
Alias=reversessh.service
'''


if args.cmd == "setupServer":
    print(runRemoteScript("installserver", "setupHere",
            sudoUsername=args.serverSudoUsername, username=args.username, port=args.port))
elif args.cmd == "createConf":
    if os.path.exists(args.output):
        raise Exception("Will not override output file")
    keys = sshKeygen()
    response = runRemoteScript("installsshkey", username=args.username,
        publicBase64=base64.b64encode(keys['public'].encode()).decode(),
        commentBase64=base64.b64encode(args.comment.encode()).decode())
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
    incomingConnection(conf, args.portRemote)
elif args.cmd == "setupIncomingService":
    if os.getuid() != 0:
        raise Exception("Must be run as sudo")
    with open(args.conf) as f:
        conf = json.load(f)
    conf['portRemote'] = args.portRemote
    with open("/etc/reversessh.conf", "w") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps(conf, indent=4))
    with open(__file__) as f:
        myself = f.read()
    with open("/usr/sbin/reversessh.py", "w") as f:
        os.fchmod(f.fileno(), 0o755)
        f.write(myself)
    with open("/lib/systemd/system/reversessh.service", "w") as f:
        f.write(SERVICE_FILE)
    subprocess.check_output(['systemctl', 'daemon-reload'])
    subprocess.check_output(['systemctl', 'enable', 'reversessh.service'])
    subprocess.check_output(['systemctl', 'restart', 'reversessh.service'])
elif args.cmd == "incomingService":
    with open(args.conf) as f:
        conf = json.load(f)
    while True:
        try:
            incomingConnection(conf, conf['portRemote'])
        except:
            logging.exception("Connection failed")
        time.sleep(5)
elif args.cmd == "link":
    with open(args.conf) as f:
        conf = json.load(f)
    outgoingConnection(conf, args.portRemote)
else:
    raise AssertionError("Unknown command: %s" % args.cmd)
