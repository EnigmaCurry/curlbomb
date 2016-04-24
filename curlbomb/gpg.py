import logging
import subprocess
from io import BytesIO

log = logging.getLogger('curlbomb.gpg')

def detect_encrypted_resource(resource):
    """Detect if resource is encrypted with GnuPG

    Determining factors:
     a) The resource is ascii-armored text
     b) The resource is binary data starting with 0x8502"""
    line = resource.read(50)
    resource.seek(0)
    if line.startswith(b"-----BEGIN PGP"):
        return True
    elif line.startswith(b'\x85\x02'):
        return True
    else:
        return False
        
def decrypt_resource_if_necessary(resource):
    """Decrypt resource and return as decrypted BytesIO.

    If resource is not encrypted, return original resource"""
    if not detect_encrypted_resource(resource):
        return resource
    log.warn("Resource appears to be encrypted, handing off to gpg for decryption...")
    with subprocess.Popen(
            ['gpg','-d'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
        p.stdin.write(resource.read())
        decrypted, stderr = p.communicate()
    if p.returncode != 0:
        raise RuntimeError("Resource failed decryption")
    decrypted_resource = BytesIO(decrypted)
    return decrypted_resource
