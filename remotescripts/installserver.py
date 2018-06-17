#!/usr/bin/python3
import os
import sys
insertToPath = os.path.join(os.path.dirname(os.path.dirname(__file__)))
os.environ['PYTHONPATH'] = insertToPath + ":" + os.environ.get('PYTHONPATH', '')
sys.path.insert(0, insertToPath)
import argparse
import subprocess

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="cmd")
setupHere = subparsers.add_parser("setupHere")
setupHere.add_argument("--username", default="reversessh")
setupHere.add_argument("--sudoUsername", default="ubuntu")
setupHere.add_argument("--port", required=True, type=int)
args = parser.parse_args()


SSHD_CONFIG_TEMPLATE = r'''
Port %(port)d
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
AllowUsers %(username)s
ForceCommand echo No commands
HostKey /home/%(username)s/ssh_host_rsa_key
PidFile /home/%(username)s/daemon.pid
ClientAliveInterval 5
ClientAliveCountMax 1
'''


SERVICE_FILE_TEMPLATE = r'''
[Unit]
Description=ReverseSSH SSH server
After=network.target auditd.service
ConditionPathExists=!/etc/reverse_sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStart=/usr/sbin/sshd -f /home/%(username)s/sshd_config
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=/home/%(username)s
RuntimeDirectoryMode=0755
User=%(username)s

[Install]
WantedBy=multi-user.target
Alias=reversesshd.service
'''


if args.cmd == "setupHere":
    subprocess.check_output(["sudo", "apt-get", "install", "fail2ban"])

    if not os.path.exists("/home/%s" % args.username):
        subprocess.check_output(["sudo", "adduser", args.username])
        print("Added user")
    else:
        print("User already exists")

    conf = open("/etc/ssh/sshd_config").read()
    if ('\nAllowUsers %s' % args.sudoUsername) not in conf:
        conf += "\nAllowUsers %s\n" % args.sudoUsername
        with open("/tmp/sshd_config", "w") as f:
            f.write(conf)
        subprocess.check_output(['sudo', 'cp', '/tmp/sshd_config', '/etc/ssh/sshd_config'])
        subprocess.check_output(['sudo', 'chown', 'root:root', '/etc/ssh/sshd_config'])
        subprocess.check_output(['sudo', 'systemctl', 'daemon-reload'])
        subprocess.check_output(['sudo', 'systemctl', 'restart', 'sshd.service'])
        print("Configured primary sshd")
    else:
        print("Primary sshd already configured")

    if not os.path.exists("/home/%s/.ssh" % args.username):
        subprocess.check_output(['sudo', 'su', '-', args.username, '-c', 'mkdir ~/.ssh'])

    if not os.path.exists("/home/%s/ssh_host_rsa_key" % args.username):
        subprocess.check_output(['sudo', 'su', '-', args.username, '-c',
            'ssh-keygen -N "" -t rsa -b 4096 -f /home/%s/ssh_host_rsa_key' % args.username])
        print("Generated new host key")
    else:
        print("Host key already exists")

    with open("/tmp/sshd_config", "w") as f:
        f.write(SSHD_CONFIG_TEMPLATE % dict(username=args.username, port=args.port))
    subprocess.check_output(['sudo', 'su', '-', args.username, '-c', 'cp /tmp/sshd_config ~'])
    with open("/tmp/reversesshd.service", "w") as f:
        f.write(SERVICE_FILE_TEMPLATE % dict(username=args.username))
    subprocess.check_output(['sudo', 'cp', '/tmp/reversesshd.service', '/lib/systemd/system/reversesshd.service'])
    subprocess.check_output(['sudo', 'systemctl', 'daemon-reload'])
    subprocess.check_output(['sudo', 'systemctl', 'enable', 'reversesshd.service'])
    subprocess.check_output(['sudo', 'systemctl', 'restart', 'reversesshd.service'])
    print("SSHD for tunneling configured and started")

else:
    raise AssertionError("Unknown command: %s" % args.cmd)
