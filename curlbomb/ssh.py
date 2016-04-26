import threading
import subprocess
import time
import logging

log = logging.getLogger('curlbomb.ssh')


class SSHRemoteForward(threading.Thread):
    def __init__(self, host, remote_forward, ssh_port=22):
        """Start an SSH connection to the specified host and remotely forward a port"""
        self.host = host
        self.ssh_port = str(ssh_port)
        self.remote_forward = remote_forward
        self._kill = False
        self._connected = False
        self._lines = []
        threading.Thread.__init__(self)

    def run(self):
        log.info("Creating ssh forward {} via {}".format(self.remote_forward, self.host))
        proc = subprocess.Popen(
            ['ssh','-v','-p',self.ssh_port,'-N','-R',self.remote_forward,self.host],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while True:
            line = proc.stdout.readline()
            self._lines.append(line)
            if line == b'':
                self._kill = True
                break
            elif b'remote port forwarding failed' in line:
                self._kill = True
            elif b"All remote forwarding requests processed" in line:
                self._connected = True
                break
        while True:
            if self._kill:
                self.last_msg = self._lines[-2].decode("utf-8")
                proc.kill()
                break
            time.sleep(0.1)

    def wait_connected(self):
        try:
            while not self._kill:
                if self._connected:
                    log.info("SSH forward established")
                    return True
                time.sleep(0.1)
            return False
        except KeyboardInterrupt:
            self.kill()
    
    def kill(self):
        self._kill = True
        self.join()
        log.info("SSH connection closed: {}".format(self.host))
