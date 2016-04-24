import sys
from io import BytesIO
import logging

from .gpg import decrypt_resource_if_necessary

log = logging.getLogger('curlbomb.run')

def add_parser(subparsers):
    run_parser = subparsers.add_parser('run', help="Run a local script on the client")
    run_parser.add_argument('-c', '--command', metavar="COMMAND",
                            help="The the shell command to curlbomb into "
                            "(default is to detect #!interpreter ie. the shebang)",
                            default=None)
    run_parser.add_argument('resource', metavar="SCRIPT", nargs='?', default=sys.stdin)
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
            settings['resource'] = open(args.resource, 'br')

    settings['resource'] = decrypt_resource_if_necessary(settings['resource'])
            
    #Detect if the input has a shebang so we can detect the shell command to display    
    if args.command is None:
        line = settings['resource'].readline(500)
        settings['resource'].seek(0)
        if line.startswith(b'#!'):
            settings['shell_command'] = line[2:].decode("utf-8").rstrip()
        else:
            settings['shell_command'] = "bash"
        
