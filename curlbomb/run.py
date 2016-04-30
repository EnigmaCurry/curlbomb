import sys
import re
from io import BytesIO
import logging
import hashlib

import requests

from .gpg import decrypt_resource_if_necessary, verify_resource

log = logging.getLogger('curlbomb.run')

def add_parser(subparsers):
    run_parser = subparsers.add_parser('run', help="Run a local script on the client")
    run_parser.add_argument('-c', '--command', metavar="COMMAND",
                            help="The the shell command to curlbomb into "
                            "(default is to detect #!interpreter ie. the shebang)")
    run_parser.add_argument('--hash', metavar="SHA256", dest="script_hash",
                            help="The sha256 hash of the resource to verify before serving")
    run_parser.add_argument("--signature", metavar=("FILE_OR_URL","GPG_ID"), nargs="+",
                            help="Verify SCRIPT against this GPG signature. "
                            "Can be a file or a http(s) URL. Specify list of GPG IDs to allow, "
                            "otherwise any in your keyring will work.")
    run_parser.add_argument('resource', metavar="SCRIPT", help="path or URL to script, or - to read from STDIN",
                            nargs='?', default=sys.stdin)
    run_parser.set_defaults(prepare_command=prepare)


def prepare(args, settings, parser):
    settings['time_command'] = True
    settings['shell_command'] = args.command

    if args.resource == sys.stdin:
        args.resource = settings['stdin']
    
    if args.resource == settings['stdin'] and settings['stdin'].isatty():
        parser.print_help()
        sys.stderr.write("\nYou must specify a file or pipe one to this command's stdin\n")
        sys.exit(1)
    if settings.get('resource', None) is None:
        if args.resource == settings['stdin'] or args.resource == '-':
            settings['resource'] = BytesIO(settings['stdin'].buffer.read())
        else:
            if re.match("http[s]?://", args.resource): 
                # Download resource from URL:
                log.info("Downloading resource: {}".format(args.resource))
                r = requests.get(args.resource)
                settings['resource'] = BytesIO(r.content)
            else:
                # Read resource from disk:
                settings['resource'] = open(args.resource, 'br')
            
    settings['resource'] = decrypt_resource_if_necessary(settings['resource'])

    if args.script_hash is not None:
        hash = hashlib.sha256(settings['resource'].read()).hexdigest()
        if args.script_hash != hash:
            log.error("Bad resource hash: {}".format(hash))
            sys.exit(1)

    if args.signature is not None:
        if not verify_resource(settings['resource'], args.signature[0], args.signature[1:]):
            log.error("Invalid signature for resource")
            sys.exit(1)

    #Detect if the input has a shebang so we can detect the shell command to display    
    if args.command is None:
        line = settings['resource'].readline(500)
        settings['resource'].seek(0)
        if line.startswith(b'#!'):
            settings['shell_command'] = line[2:].decode("utf-8").rstrip()
        else:
            settings['shell_command'] = "bash"
        
