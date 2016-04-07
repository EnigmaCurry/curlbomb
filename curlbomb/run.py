import sys
from io import BytesIO
import logging

log = logging.getLogger('curlbomb.run')

def prepare(args, settings, parser):
    settings['time_command'] = True
    settings['shell_command'] = args.command

    if args.resource == sys.stdin:
        args.resource = settings['stdin']
    
    if args.resource == settings['stdin'] and settings['stdin'].isatty():
        parser.print_help()
        sys.stderr.write("\nYou must specify a file or pipe one to this command's stdin\n")
        sys.exit(1)
    if args.resource == settings['stdin'] or args.resource == '-':
        settings['resource'] = BytesIO(settings['stdin'].buffer.read())
    else:
        settings['resource'] = open(args.resource, 'br')

    #Detect if the input has a shebang so we can detect the shell command to display    
    if args.command is None:
        line = settings['resource'].readline(500)
        settings['resource'].seek(0)
        if line.startswith(b'#!'):
            settings['shell_command'] = line[2:].decode("utf-8").rstrip()
        else:
            settings['shell_command'] = "bash"
        
