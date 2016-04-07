import logging
import glob
from io import BytesIO
import os

from . import run

log = logging.getLogger('curlbomb.ping')

script = """#!/bin/bash
set -e
SSH_PUBKEY="{ssh_id}"
AUTH_FILE="$HOME/.ssh/authorized_keys"

# If ssh dir does not exist, create it:
if [ ! -d "$HOME/.ssh" ]; then
    mkdir $HOME/.ssh
    chmod 711 $HOME/.ssh
fi

# If authorized_keys file does not exist, create it:
if [ ! -f "$AUTH_FILE" ]; then
    touch $AUTH_FILE
    chmod 700 $AUTH_FILE
fi

# Don't add the key if it's already there:
if ! grep -q "$SSH_PUBKEY" $AUTH_FILE; then
    # Detect if the file is blank:
    if [[ $(cat $AUTH_FILE | wc -c) -gt 1 ]]; then
        # Detect if file does not end in a newline, adds one if necessary:
        if [[ $(tail -n 1 "$AUTH_FILE" | wc --lines) -lt 1 ]]; then 
            echo "" >> $AUTH_FILE
        fi
    fi
    echo "$SSH_PUBKEY" >> $AUTH_FILE
fi
"""

class SSHIdentityException(Exception):
    pass

def add_parser(subparsers):
    parser = subparsers.add_parser(
        'ssh-copy-id', help="copy ssh public key to remote authorized_keys file")
    parser.add_argument('identity', metavar="IDENTITY",
                        help="Read identity from SSH identity file (eg ~/.ssh/id_rsa.pub)")
    parser.set_defaults(prepare_command=prepare)

def get_pubkey(identity):
    if not os.path.isfile(identity):
        raise SSHIdentityException("identity file does not exist: {}".format(identity))
    if not identity.endswith(".pub"):
        raise SSHIdentityException("identity file name must end with .pub")

    with open(identity) as f:
        pubkey = f.read().strip()
    assert len(pubkey.splitlines()) == 1, "SSH identity file has more than one line"
    return pubkey
    
def prepare(args, settings, parser):
    args.resource = settings['resource'] = BytesIO(bytes(script.format(ssh_id = get_pubkey(args.identity)), "utf-8"))

    # Call the run prepare method
    args.command = None
    run.prepare(args, settings, parser)
