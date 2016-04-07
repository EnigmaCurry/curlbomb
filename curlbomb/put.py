import glob
import os
import shlex
import subprocess
import logging

log = logging.getLogger('curlbomb.put')

def add_parser(subparsers):
    put_parser = subparsers.add_parser(
        'put', help='Copy local files or directories to the client')
    put_parser.add_argument('source', metavar="SOURCE", nargs=1,
                            help="Local path to copy (or put glob in quotes)")
    put_parser.add_argument('dest', metavar="DEST", nargs='?',
                            help="Remote directory to copy to")
    put_parser.add_argument('--exclude', metavar="PATTERN", action='append',
                            help="Exclude files matching PATTERN, "
                            "a glob(3)-style wildcard pattern", default=[])
    put_parser.set_defaults(prepare_command=prepare)


def prepare(args, settings, parser):
    path = glob.glob(args.source[0])[0]
    parent_path, path = os.path.split(os.path.abspath(path))
    exclude_args = " ".join(["--exclude='{}'".format(p) for p in args.exclude])
    cmd = shlex.split('tar czh {exclude} -C "{parent_path}" "{path}"'.format(
        parent_path=parent_path, path=path, exclude=exclude_args))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    args.resource = settings['resource'] = p.stdout
    if args.dest:
        settings['shell_command'] = 'cd "{dest}" && tar xzvf'.format(dest=args.dest)
    else:
        settings['shell_command'] = 'tar xzvf'
