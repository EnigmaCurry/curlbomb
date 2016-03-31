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

## TODO: Finish these tests... they don't work yet

def run_curlbomb(args):
    """Run curlbomb for testing purposes
    
    - Start the server with the given args
    - Run client
    - Return output from curlbomb and client
    """
    settings = curlbomb.parse_args(args)
    curlbomb_cmd = curlbomb.get_wrapped_curlbomb_command(settings)
    
    threading.Thread(target=curlbomb.run_server, args=(settings,)).start()
    
    client_proc = subprocess.Popen(curlbomb_cmd, shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
    client_out = client_proc.communicate()[0]
    return client_out

client_scripts = {
    'long': b"echo 'start' && sleep 3 && echo 'done'",
    'short': b"echo 'hello'"
}
    
command_args = {
    'default': ('-q', client_scripts['long'])
}
    
def test_commands():
    for name, (args, script) in command_args.items():
        with NamedTemporaryFile() as f:
            f.write(script)
            f.flush()
            client_out = run_curlbomb(shlex.split("{} {}".format(args, f.name)))
        print(client_out)
