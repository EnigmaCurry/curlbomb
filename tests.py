import threading
import subprocess
import re
import os
import shlex
import time
import curlbomb
import sys
from io import TextIOWrapper, BytesIO
from tempfile import NamedTemporaryFile
import logging
import socket
import unittest
import tornado
import tempfile
import hashlib
import shutil

log = logging.getLogger("curlbomb.test")
log.setLevel(level=logging.INFO)

client_scripts = {
    'long': ("echo 'start' && sleep 2 && echo 'done'", "start\ndone\n"),
    'short': ("echo 'hello'", "hello\n"),
    'python': ("#!/usr/bin/env python3\nprint(2+2)","4\n"),
    'python_no_shebang': ("print(2+2)","4\n")    
}



class CurlbombThread(threading.Thread):
    def __init__(self, settings):
        threading.Thread.__init__(self)
        self.__settings=settings
        
    def run(self):
        log.info('Starting server')
        try:
            curlbomb.run_server(self.__settings)
        finally:
            log.info('Server finished')

class CurlbombTestBase(unittest.TestCase):

    def get_curlbomb(self, args, script=None):
        """Prepare curlbomb to run in a thread

        Assumes args has a '{script}' formatter in it to replace a temporary path with
        If no '{script}' formatter is found, stdin is mocked through settings['stdin']

        Returns tuple(curlbomb_thread, client_command)
        """
        if type(script) == str:
            script = bytes(script, "utf-8")
        stdin = "{script}" not in args and script is not None
        try:
            override_defaults = {}
            log.info("Using stdin: {}".format(stdin))
            if stdin:
                s = TextIOWrapper(BytesIO(script))
                override_defaults['stdin'] = s
            else:
                s = NamedTemporaryFile()
                if script is not None:
                    s.write(script)
                    s.flush()
                    args = args.format(script=s.name)
            args = shlex.split(args)
            log.info("starting curlbomb: {}".format(args))
            settings = curlbomb.get_settings(args, override_defaults)
            client_cmd = curlbomb.get_curlbomb_command(settings)
            curlbomb_thread = CurlbombThread(settings)
            curlbomb_thread.start()
            return (curlbomb_thread,
                    client_cmd)
        finally:
            s.close()

    def run_client(self, client_cmd, expected_out=None, expected_err=None):
        # Have to run explicitly in bash to get subprocesses to work:
        client_cmd = ['bash','-c',client_cmd]
        log.info("starting client: {}".format(client_cmd))
        client_proc = subprocess.Popen(client_cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        client_out, client_err = client_proc.communicate()
        client_out = client_out.decode("utf-8")
        client_err = client_err.decode("utf-8")
        log.info('client out: {}'.format(repr(client_out)))
        if expected_out is not None:
            self.assertEquals(client_out, expected_out)
        if expected_err is not None:
            self.assertIsNotNone(expected_err.search(client_err))

        return client_out, client_err

    def simple_runner(self, args, script, expected_out):
        cb, client_cmd = self.get_curlbomb(args, script)
        client_out, client_err = self.run_client(client_cmd, expected_out)
        return (cb, client_cmd, client_out, client_err)

    def test_default_args(self):
        self.simple_runner('', *client_scripts['short'])

    def test_no_knock(self):
        self.simple_runner('-k', *client_scripts['short'])

    def test_knock(self):
        script, expected_out = client_scripts['short']
        cb, client_cmd = self.get_curlbomb('', script)
        self.assertTrue(client_cmd.startswith("KNOCK"))
        # Test without knock:
        client_cmd_no_knock=" ".join(client_cmd.split(" ")[1:]) 
        client_out, client_err = self.run_client(client_cmd_no_knock, 'Invalid knock\r\n')
        # Test again with knock:
        client_out, client_err = self.run_client(client_cmd, expected_out)

    def test_multi_gets(self):
        script, expected_out = client_scripts['short']
        cb, client_cmd = self.get_curlbomb('-v -n 4', script)
        for x in range(4):
            self.run_client(client_cmd, expected_out)
        # Run a fifth time should fail:
        self.run_client(client_cmd, '', re.compile("^curl.*Connection refused"))

    def test_specific_port(self):
        # Get a random free port:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('',0))
        port = s.getsockname()[1]
        s.close()
        self.simple_runner('-p {}'.format(port), *client_scripts['short'])

    def test_python(self):
        self.simple_runner('', *client_scripts['python'])

    def test_alternate_command(self):
        self.simple_runner('-v run -c python', *client_scripts['python_no_shebang'])

    def test_wget(self):
        self.simple_runner('-w', *client_scripts['short'])

    def test_survey(self):
        self.simple_runner('--survey', 'just text', 'just text')

    def test_survey_wget(self):
        self.simple_runner('--survey -w', 'just text', 'just text')

    def test_unwrapped_command(self):
        script, expected_out = client_scripts['short']
        cb, client_cmd = self.get_curlbomb('--unwrapped run -c source', script)
        self.assertTrue(client_cmd.startswith('source '))
        client_out, client_err = self.run_client(client_cmd, expected_out)

    def test_domain(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('',0))
        port = s.getsockname()[1]
        s.close()
        cb, client_cmd, out, err = self.simple_runner(
            '-p {port} -d localhost:{port}'.format(port=port),
            *client_scripts['short'])
        self.assertTrue("http://localhost:{port}".format(port=port) in client_cmd)


    def test_log_posts(self):
        script, expected_out = client_scripts['short']
        cb, client_cmd = self.get_curlbomb('-l', script)
        try:
            # Capture stdout via temporary monkey patch :
            original_stdout = sys.stdout
            out = sys.stdout = TextIOWrapper(BytesIO())
            client_out, client_err = self.run_client(client_cmd, expected_out)
            out.seek(0)
            self.assertEquals(out.read(), client_out)
        finally:
            sys.stdout = original_stdout

    def test_unwrapped(self):
        self.simple_runner('--unwrapped', *client_scripts['short'])

    def __get_directory_contents(self, path):
        """Get filenames of a directory in tar-like output format"""
        parent_path, path_name = os.path.split(path)
        contents = []
        for root, dirs, files in os.walk(path):
            contents.append(os.path.relpath(root,  parent_path) + '/')
            for f in files:
                contents.append(os.path.relpath(os.path.join(root, f), parent_path))
        return sorted(contents)

    def __get_directory_sha256(self, path):
        """Get sha256sum of each file in a directory, recursively"""
        parent_path, path_name = os.path.split(path)
        path_shas = {} # path -> sha
        for root, dirs, files in os.walk(path):
            for fn in (os.path.join(root, f) for f in files):
                with open(fn) as f:
                    path_shas[os.path.relpath(fn, parent_path)] = hashlib.sha256(
                        f.read().encode('utf-8')).hexdigest()
        return path_shas

    def __put_get_test(self, operation):
        curdir = os.path.abspath(os.path.curdir)
        try:
            # Transfer a single test directory recursively
            test_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'test_scripts', 'some_files')
            contents = self.__get_directory_contents(test_path)
            test_shas = self.__get_directory_sha256(test_path)

            def dest_assert(client_out, destdir):
                if operation=='put':
                    # Make sure client out matches the directory listing:
                    self.assertEqual(sorted(client_out.splitlines()), contents)
                # Make sure the destination actually contains all the files:
                dest_contents = self.__get_directory_contents(
                    os.path.join(destdir, 'some_files'))
                self.assertEqual(contents, dest_contents)
                # Make sure the contents of each file are identical:
                self.assertEqual(test_shas, self.__get_directory_sha256(
                    os.path.join(destdir, 'some_files')))
            
            # put/get operation with explicit destination directory:
            with tempfile.TemporaryDirectory() as tempdir:
                os.chdir(tempdir)
                with tempfile.TemporaryDirectory() as destdir:
                    try:
                        cb, client_cmd = self.get_curlbomb('{operation} {source} {dest}'.format(
                            operation=operation, source=test_path, dest=destdir))
                        client_out, client_err = self.run_client(client_cmd)
                        cb.join()
                        dest_assert(client_out, destdir)
                    finally:
                        pass
            
            # put/get operation with implicit destination directory:
            with tempfile.TemporaryDirectory() as tmpdir:
                os.chdir(tmpdir)
                cb, client_cmd = self.get_curlbomb('{operation} {source}'.format(
                    operation=operation, source=test_path))
                client_out, client_err = self.run_client(client_cmd)
                cb.join()
                dest_assert(client_out, tmpdir)

        finally:
            os.chdir(curdir)

    def test_put(self):
        self.__put_get_test('put')

    def test_get(self):
        self.__put_get_test('get')

    def test_ssl(self):
        script, expected_out = client_scripts['short']
        ca_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'test_scripts/tls')
        ca_pem = os.path.join(ca_dir, 'test.pem')
        ca_chain = os.path.join(ca_dir, 'test_chain.pem')
        cb, client_cmd = self.get_curlbomb(
            '--domain localhost --ssl {ca_pem}'.format(ca_pem=ca_pem), script)
        # Try running without SSL certificate authority known:
        client_out, client_err = self.run_client(client_cmd)
        self.assertTrue("SSL certificate problem" in client_err)
        # Try again by instructing curl where to find the CA cert:
        os.environ['CURL_CA_BUNDLE'] = ca_chain
        try:
            client_out, client_err = self.run_client(client_cmd, expected_out)
        finally:
            del os.environ['CURL_CA_BUNDLE']
            
