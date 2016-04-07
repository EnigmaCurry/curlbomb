import glob
import os
import shlex
import subprocess
import logging

log = logging.getLogger('curlbomb.put')

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
