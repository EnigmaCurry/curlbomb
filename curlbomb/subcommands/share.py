import sys
from io import BytesIO
from collections import OrderedDict
import urllib
import shlex
import subprocess
import logging

from .. import argparser

log = logging.getLogger('curlbomb.share')

def add_parser(subparsers):
    share_parser = subparsers.add_parser(
        'share', help="Share a resource URL with any number of people.")
    share_args = share_parser.add_argument_group("share args", "Share a resource URL with any number of people")

    share_args.add_argument('resource', metavar="FILE", help="path of file to share, or - to read from STDIN",
                              nargs='?', default=sys.stdin)

    argparser.add_inheritible_args(share_parser, "share")
    
    share_parser.set_defaults(subcommand="share", prepare_command=prepare)

def prepare(args, settings, parser):
    settings['survey'] = True
    settings['receive_postbacks'] = False
    settings['num_gets'] = argparser.get_arg_value(args, "num_gets", 0)

    if settings['num_gets'] == 0:
        log.warn("server set to serve resource an unlimited number of times (-n 0)")
    
    # Share command outputs just a URL to share rather than a curlbomb:
    def get_share_command(settings, unwrapped=None):
        params = OrderedDict()
        if settings['require_knock']:
            params['knock'] = settings['knock']
        
        return "http{ssl}://{host}:{port}/r{query_params}".format(
            ssl="s" if settings['ssl'] is not False else "",
            host=settings['display_host'],
            port=settings['display_port'],
            query_params="?"+urllib.parse.urlencode(
                params) if len(params)>0 else ""
            )
    settings['get_curlbomb_command'] = get_share_command

    
    if args.resource == sys.stdin:
        args.resource = settings['stdin']
    if args.resource == settings['stdin'] and settings['stdin'].isatty():
        parser.print_help()
        sys.stderr.write("\nYou must specify a file or pipe one to this command's stdin\n")
        sys.exit(1)

    if settings.get('resource', None) is None:
        if args.resource == settings['stdin'] or args.resource == '-':
            # Read resource from stdin:
            settings['resource'] = BytesIO(settings['stdin'].buffer.read())
        else:
            # Read resource from disk:
            settings['resource'] = open(args.resource, 'br')
