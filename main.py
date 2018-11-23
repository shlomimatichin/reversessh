#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK
import os
import sys
import argparse
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

parser = argparse.ArgumentParser(
    description="Reverse ssh tunnels to a central cloud server, allowing you ssh access to servers behind "
    "firewalls. Use the 'readme' command to read more.",
    epilog="Quick start: 1. setup the central server once, using 'setupServer'. Then for each server you "
    "wish to add to the network: 2. use 'createConf' using the root credentials, 3. copy the resulting 'conf' "
    "file to the new host, and use 'setupIncomingService' (make sure to assign a new remotePort). Use 'readme' "
    "command to learn more")
subparsers = parser.add_subparsers(dest="cmd")
setupCmd = subparsers.add_parser(
    "setupServer",
    help="Set up the central server. Do this once for each network")
setupCmd.add_argument("--server", required=True,
                      help="server hostname / ip address")
setupCmd.add_argument("--serverSudoUsername", default="ubuntu",
                      help="The user that can do sudo without password. this is "
                      "used only during setup, the server is started as a new unpriviledged user. "
                      "This script assumes you have the password for this user, or a ssh key identity "
                      "already set up. On EC2 instances of ubuntu, this is usually 'ubuntu'. Amazon linux "
                      "is usually 'root'.")
setupCmd.add_argument("--username", default="reversessh",
                      help="the name of the unpriviledged user to create, for running the "
                      "tunneling sshd. Dont override this for any simple cases.")
setupCmd.add_argument("--port", type=int, required=True,
                      help="the port for the unpriviledged sshd to run on. must be open for incoming "
                      "tcp connection on the server (e.g., if using ec2, security group must have this "
                      "port open)")
createConfCmd = subparsers.add_parser(
    "createConf",
    help="First step for adding another server to the reversessh network. This command is run on the "
    "administrator machine, and uses the priviledged user to create a 'conf' file. In the second step, "
    "This file is then transferred to the new host, where it can be used to install the connection "
    "service")
createConfCmd.add_argument("--server", required=True,
                           help="The central server hostname / ip address")
createConfCmd.add_argument("--serverSudoUsername", default="ubuntu",
                           help="The user that can do sudo without password. this is "
                           "used only during setup, the server is started as a new unpriviledged user. "
                           "This script assumes you have the password for this user, or a ssh key identity "
                           "already set up. On EC2 instances of ubuntu, this is usually 'ubuntu'. Amazon linux "
                           "is usually 'root'.")
createConfCmd.add_argument("--username", default="reversessh",
                           help="the name of the unpriviledged user to created when setting up the server. "
                           "This user runs the tunneling sshd. Dont override this for any simple cases.")
createConfCmd.add_argument("--port", type=int, required=True,
                           help="the port for the unpriviledged sshd to run on. must be open for incoming "
                           "tcp connection on the server (e.g., if using ec2, security group must have this "
                           "port open)")
createConfCmd.add_argument("--output", default="reversessh.conf",
                           help="the output created, this file is transferred to the new host joining the "
                           "network and used with 'setupIncomingService'")
createConfCmd.add_argument("--comment", required=True,
                           help="Each time you create a conf, a new key is created and added to the file "
                           "/home/reversessh/.ssh/authorized_keys . This comment will preceed the new line "
                           "and helps manages the created keys, and delete if required. The suggested format "
                           "for this comment is to also add the reverse port of the host to be added (i.e., "
                           "the same --portRemote from 'setupIncomingService' to be run afterwards), since "
                           "there is no other place where a list of the ports exists")
testIncomingCmd = subparsers.add_parser(
    "testIncoming",
    help="An optional step when adding a new server: after creation of the 'conf' file, you can test "
    "that it works correctly using this command, either on the admin station, or the target host to be "
    "added to the network")
testIncomingCmd.add_argument("--conf", default="reversessh.conf",
                             help="the 'conf' file created in the 'createConf' step, you wish to test")
testIncomingCmd.add_argument("--portRemote", type=int, required=True,
                             help="The assigned port you are going to use this conf and host file for. "
                             "use ./main.py setupIncomingService --help to learn more about this")
setupIncomingServiceCmd = subparsers.add_parser(
    "setupIncomingService",
    help="This is the second step in adding a new host. After creating a conf file, and transferring it "
    "to the new host, run this. MUST BE RUN AS ROOT. It will setup a systemd service for continuously "
    "opening an ssh tunnel, so the tunnel will work even after reboots and disconnects. Once this completes, "
    "you will be able to access this host from the central server.")
setupIncomingServiceCmd.add_argument("--conf", required=True,
                                     help="The 'conf' file created in the previous step, 'createConf'")
setupIncomingServiceCmd.add_argument("--portRemote", type=int, required=True,
                                     help="The remote port assigned to this new host. Each host forwards one "
                                     "port from the central server (localhost) to its local port 22. You need "
                                     "to assign a different port to each host. For example, use running numbers "
                                     "2000, 2001, 2002,... ")
incomingServiceCmd = subparsers.add_parser(
    "incomingService",
    help="When setting up the service, it copies the script to the local machine, and this is what systemd "
    "will actually run. Don't invoke this directly from the command line")
incomingServiceCmd.add_argument("--conf", default="/etc/reversessh.conf")
incomingServiceCmd.add_argument("--deviceRegexWhenNoDefaultRoute")
incomingServiceCmd.add_argument("--suspendWhilePidLivesFile", default="/etc/reversessh.suspend.pidfile")
linkCmd = subparsers.add_parser(
    "link",
    help="To access hosts connected to the central server, you need to ssh to the server first, and forward "
    "the relevant remote ports, to open an ssh connection directly to them. You can do this in one of two ways: "
    "Either use your credentials and ssh 'normally' to the server, adding a -L parameter to ssh (e.g., 'ssh "
    "ubuntu@central_server -L 2000:localhost:2000 -N'), or use this command. The advantages of using "
    "this command: it can handle multiple source routes to the central server (e.g., a device with several "
    "cellular modems), and it uses a conf file, instead of root credentials (which means the user can only "
    "port forward things, doesn't have ssh access to the central server)")
linkCmd.add_argument("--conf", default="reversessh.conf",
                     help="A 'conf' file created with 'createConf'")
linkCmd.add_argument("--portRemote", type=int, required=True, nargs="+",
                     help="a space separated list of ports to forward")
linkCmd.add_argument("--deviceRegexWhenNoDefaultRoute",
                     help="if no default route exists, check source routing tables and try one of these devices")
readmeCmd = subparsers.add_parser("readme")
try:
    import argcomplete
    argcomplete.autocomplete(parser)
except:
    pass
args = parser.parse_args()


def runRemoteScript(name, *pargs, **kwargs):
    filename = os.path.join(os.path.dirname(__file__), "remotescripts", "%s.py" % name)
    encoded = base64.b64encode(open(filename, "rb").read()).decode()
    arguments = " ".join(["'%s'" % a for a in pargs] + ["'--%s=%s'" % (k, v) for k, v in kwargs.items()])
    return subprocess.check_output([
        "ssh", "%s@%s" % (args.serverSudoUsername, args.server),
        "echo %s | base64 -d | python3 - %s" % (encoded, arguments)]).decode()


def sshKeygen():
    hostsFile = tempfile.mktemp()
    subprocess.check_call(["ssh-keygen", '-N', '', '-t', 'rsa', '-b', '4096', '-f', hostsFile])
    try:
        with open(hostsFile) as hostsFileHandle:
            private = hostsFileHandle.read()
        with open(hostsFile + ".pub") as hostFilePub:
            public = hostFilePub.read()
        return dict(public=public, private=private)
    finally:
        os.unlink(hostsFile)


def route():
    output = subprocess.check_output(["ip", "route", "show"]).decode()
    if 'default via' in output:
        print("Found default route")
        return []
    if hasattr(args, 'deviceRegexWhenNoDefaultRoute') and args.deviceRegexWhenNoDefaultRoute:
        options = [line for line in output.split("\n")
                   if re.search("dev " + args.deviceRegexWhenNoDefaultRoute, line) is not None]
        if not options:
            raise Exception("No route and no deviceRegexWhenNoDefaultRoute devices")
        line = options[random.randrange(0, len(options))]
        sourceAddress = re.search(r"src (\d+\.\d+\.\d+\.\d+)", line).group(1)
        print("Attempting to use %s as source address" % sourceAddress)
        return ['-b', sourceAddress]
    raise Exception("No route")


def incomingConnection(conf, portRemote):
    ssh(conf, route() + ["-R", "%d:localhost:22" % portRemote])


def outgoingConnection(conf, portRemote):
    extra = route()
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
    child = subprocess.Popen(
        ["ssh",
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
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
Alias=reversessh.service
'''


def killPreviousSSH(conf):
    lines = subprocess.check_output(["ps", "-Af"]).decode().strip().split("\n")
    for line in lines:
        if 'ssh' not in line:
            continue
        if ("%s@%s" % (conf['username'], conf['server'])) not in line:
            continue
        pid_of_ssh = int(re.findall(r"\w+", line)[1])
        os.kill(pid_of_ssh, signal.SIGTERM)


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
        conf_contents = json.load(f)
    incomingConnection(conf_contents, args.portRemote)
elif args.cmd == "setupIncomingService":
    if os.getuid() != 0:
        raise Exception("Must be run as sudo")
    with open(args.conf) as f:
        conf_contents = json.load(f)
    conf_contents['portRemote'] = args.portRemote
    with open("/etc/reversessh.conf", "w") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(json.dumps(conf_contents, indent=4))
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
        conf_contents = json.load(f)
    killPreviousSSH(conf_contents)
    if os.path.exists(args.suspendWhilePidLivesFile):
        with open(args.suspendWhilePidLivesFile) as f:
            pidText = f.read().strip()
            try:
                pid = int(pidText)
            except:
                pid = "nosuchpid"
        print("Suspended, waiting for PID %s to die" % pid)
        while os.path.exists("/proc/%s" % pid):
            time.sleep(2)
        print("Pid %d died, resuming reversessh" % pid)
        os.unlink(args.suspendWhilePidLivesFile)
    while True:
        try:
            incomingConnection(conf_contents, conf_contents['portRemote'])
        except:
            logging.exception("Connection failed")
        time.sleep(5)
elif args.cmd == "link":
    with open(args.conf) as f:
        conf_contents = json.load(f)
    outgoingConnection(conf_contents, args.portRemote)
elif args.cmd == "readme":
    print("""
reversessh.py
-------------

PURPOSE: access hosts behind firewall or nat with SSH, without introducing new security issues.
HOW: using a center cloud server. Each host is responsible for forwarding a port from that central
cloud server, (e.g., port 2000, 2001, 2002...) to it's local ssh daemon (port 22). The user can
then forward a port from his machine, to the central cloud server, and when that's ready, can
ssh to his local port and reach that host. The hosts all use ssh link to create the forwarding,
and a special unprivilidged instance of sshd runs on the central cloud server to facilitate
those links.
""")
else:
    raise AssertionError("Unknown command: %s" % args.cmd)
