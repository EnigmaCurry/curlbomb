import os
import subprocess
from io import BytesIO
import logging

log = logging.getLogger('curlbomb.get')

def add_parser(subparsers):
    get_parser = subparsers.add_parser(
        'get', help='Copy remote files or directories to the server')
    get_parser.add_argument('source', metavar="SOURCE", nargs=1,
                            help="Remote path to copy (or put glob in quotes)")
    get_parser.add_argument('dest', metavar="DEST", nargs='?',
                            help="Local directory to copy to")
    get_parser.add_argument('--exclude', metavar="PATTERN", action='append',
                            help="Exclude files matching PATTERN, "
                            "a glob(3)-style wildcard pattern", default=[])
    get_parser.set_defaults(prepare_command=prepare)


def prepare(args, settings, parser):
    settings['client_quiet'] = True
    settings['receive_postbacks'] = True
    if args.dest is None:
        dest = os.curdir
    else:
        dest = args.dest
    p = subprocess.Popen(['tar','xzv','-C',dest], stdin=subprocess.PIPE)
    settings['log_process'] = p
    settings['log_file'] = p.stdin
    parent_path, path = os.path.split(args.source[0])
    if len(parent_path) == 0:
        parent_path = os.curdir
    exclude_args = " ".join(["--exclude='{}'".format(p) for p in args.exclude])
    args.resource = settings['resource'] = BytesIO(
        bytes('tar czh {exclude} -C "{parent_path}" "{path}"'.format(
            parent_path=parent_path, path=path, exclude=exclude_args), "utf-8"))
