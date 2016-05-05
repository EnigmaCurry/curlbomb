import logging
import subprocess
import requests
import re
import tempfile
from io import BytesIO

log = logging.getLogger('curlbomb.gpg')

class GPGExceptionError(Exception):
    pass

def detect_encrypted_resource(resource):
    """Detect if resource is encrypted with GnuPG

    Determining factors:
     a) The resource is ascii-armored text
     b) The resource is binary data starting with 0x8502"""
    try:
        # Read file like
        line = resource.read(50)
        resource.seek(0)
    except AttributeError:
        # Read str like
        line = resource[:50]
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

def encrypt_resource_to_recipients(resource, recipients):
    """Encrypt resource to a list of GPG IDs"""
    cmd = ['gpg', '--batch', '-e', *['-r {}'.format(r) for r in recipients]]
    log.debug(cmd)
    with subprocess.Popen(cmd,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as p:
        p.stdin.write(resource.read())
        encrypted, stderr = p.communicate()
        if p.returncode != 0:
            log.error(stderr)
            raise RuntimeError("Resource failed to encrypt (public-key)")
        encrypted_resource = BytesIO(encrypted)
        return encrypted_resource
    
def encrypt_resource_symmetric(resource, passphrase):
    """Encrypt resource with passphrase"""
    with subprocess.Popen(['gpg', '--batch', '-c','--passphrase-fd','0'],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as p:
        p.stdin.write(bytes(passphrase, "utf-8"))
        p.stdin.write(b"\n")
        p.stdin.write(resource.read())
        encrypted, stderr = p.communicate()
        if p.returncode != 0:
            log.error(stderr)
            raise RuntimeError("Resource failed to encrypt (symmetric)")
        encrypted_resource = BytesIO(encrypted)
        return encrypted_resource
    
def gpg_key_info(identifier):
    with subprocess.Popen(
            ['gpg','-k',identifier],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
        out, err = p.communicate()
        if p.returncode != 0:
            raise GPGExceptionError("Unknown key for id: {}".format(identifier))
        return out

def verify_resource(resource, signature, allowed_authors=[]):
    """Verify signature is valid for resource

    allowed_authors is a list of GPG IDs that the signature is allowed to be from.
    If len(allowed_authors) == 0, any valid signature works.
    """
    if re.match("http[s]?://", signature):
        # Download signature:
        log.info("Downloading signature file: {}".format(signature))
        r = requests.get(signature)
        sig = r.content
    else:
        with open(signature, 'rb') as f:
            sig = f.read()

    with tempfile.NamedTemporaryFile() as sig_file, \
         tempfile.NamedTemporaryFile() as resource_file:
        # Write signature and resource to temp files:
        sig_file.write(sig)
        sig_file.flush()
        resource_file.write(resource.read())
        resource_file.flush()
        resource.seek(0)

        log.debug("signature temp file: {}".format(sig_file.name))
        log.debug("resource temp file: {}".format(resource_file.name))

        with subprocess.Popen(
                ['gpg', '--verify', sig_file.name, resource_file.name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            out, err = p.communicate()
            err = str(err, "utf-8")
            log.debug("gpg returned: {}".format(p.returncode))
            if p.returncode == 0:
                m = re.search('Good signature from \"(.*)\"', err, re.MULTILINE)
                if m:
                    fingerprint = m.groups()[0]
                    fingerprint_info = gpg_key_info(fingerprint)
                    for author in allowed_authors:
                        if gpg_key_info(author) == fingerprint_info:
                            log.warn("Matched good signature to allowed author"
                                     ": {}".format(author))
                            return True
                    if len(allowed_authors) == 0:
                        log.warn("Resource matched good signature to: {}".format(fingerprint))
                        return True
                else:
                    raise GPGExceptionError(
                        "GPG did not list a valid fingerprint even though it returned 0")
    return False
