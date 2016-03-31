import threading
import subprocess
import re
import os
import shlex
import time
import curlbomb
import sys
from io import BytesIO
from tempfile import NamedTemporaryFile
import logging
import socket

log = logging.getLogger("curlbomb.test")
log.setLevel(level=logging.INFO)

def get_curlbomb(args, script):
    """Prepare curlbomb to run in a thread

    Returns tuple(curlbomb_thread, client_command)
    """
    with NamedTemporaryFile() as s:
        s.write(bytes(script, "utf-8"))
        s.flush()
        if type(args) == str:
            args += " {file}".format(file=s.name)
            args = shlex.split(args)
        else:
            args.append(s.name)    
        settings = curlbomb.parse_args(args)
        client_cmd = curlbomb.get_curlbomb_command(settings)
        curlbomb_thread = threading.Thread(target=curlbomb.run_server, args=(settings,))
        log.info("starting curlbomb: {}".format(args))
        curlbomb_thread.start()
        return (curlbomb_thread,
                client_cmd)

def run_client(client_cmd, expected_out, expected_err=None):
    # Have to run explicitly in bash to get subprocesses to work:
    client_cmd = ['bash','-c',client_cmd]
    log.info("starting client: {}".format(client_cmd))
    client_proc = subprocess.Popen(client_cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    client_out, client_err = client_proc.communicate()
    client_out = client_out.decode("utf-8")
    client_err = client_err.decode("utf-8")
    log.info('client out: {}'.format(repr(client_out)))
    assert client_out == expected_out
    if expected_err:
        assert expected_err.search(client_err) is not None

    return client_out, client_err

client_scripts = {
    'long': ("echo 'start' && sleep 3 && echo 'done'", "start\ndone\n"),
    'short': ("echo 'hello'", "hello\n"),
    'python': ("#!/usr/bin/env python3\nprint(2+2)","4\n"),
    'python_no_shebang': ("print(2+2)","4\n")
    
}

def simple_runner(args, script, expected_out):
    cb, client_cmd = get_curlbomb(args, script)
    client_out, client_err = run_client(client_cmd, expected_out)

def test_default_args():
    simple_runner('', *client_scripts['short'])

def test_multi_gets():
    script, expected_out = client_scripts['short']
    cb, client_cmd = get_curlbomb('-v -n 4', script)
    for x in range(4):
        run_client(client_cmd, expected_out)
    # Run a fifth time should fail:
    run_client(client_cmd, '', re.compile("^curl.*Connection refused"))

def test_specific_port():
    # Get a random free port:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('',0))
    port = s.getsockname()[1]
    s.close()
    simple_runner('-p {}'.format(port), *client_scripts['short'])
    
def test_python():
    simple_runner('', *client_scripts['python'])

def test_alternate_command():
    simple_runner('-c python', *client_scripts['python_no_shebang'])

def test_wget():
    simple_runner('-w', *client_scripts['short'])

def test_survey():
    simple_runner('--survey', 'just text', 'just text')
    
def test_survey_wget():
    simple_runner('--survey -w', 'just text', 'just text')

def test_unwrapped_command():
    script, expected_out = client_scripts['short']
    cb, client_cmd = get_curlbomb('--unwrapped -c source', script)
    assert client_cmd.startswith('source ')
    client_out, client_err = run_client(client_cmd, expected_out)
