import subprocess
import tempfile
import logging
import ssl
import base64

from . import gpg

log = logging.getLogger('curlbomb.ssl')

def decrypt_cert_if_necessary(cert):
    """GPG decrypt cert pem"""
    if gpg.detect_encrypted_resource(cert):
        log.info("Attempting SSL certificate decryption")
        with subprocess.Popen(
                ['gpg','-d'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            p.stdin.write(cert)
            decrypted_cert, stderr = p.communicate()
            log.info(stderr.decode("utf-8"))
            if p.returncode != 0:
                raise RuntimeError("Could not load encrypted certificate")
            return decrypted_cert
    else:
        log.warn("SSL certificate is plain text, consider gpg encrypting it.")
        return cert

def get_pubkey_as_der(pem):
    """Extract the public key from a private pem formatted cert formatted as DER"""
    with subprocess.Popen(
            ['openssl', 'rsa', '-pubout', '-outform', 'DER'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE) as p:
        p.stdin.write(pem)
        der, err = p.communicate()
        return der

def get_pubkey_digest(der):
    """Get the sha256 digest of the pubkey in der format"""
    with subprocess.Popen(
            ['openssl', 'dgst', '-sha256', '-binary'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE) as p:
        p.stdin.write(der)
        digest, err = p.communicate()
        return digest

def create_ssl_ctx(pem):
    """Create temporary file to store plain-text cert and create ssl
    context from it.

    This doesn't seem really secure since it requires using the
    filesystem, but I can't see another way as the low-level openssl
    api requires a file and will not accept a string or file like
    object.

    """
    with tempfile.NamedTemporaryFile('wb') as temp_cert:
        temp_cert.write(pem)
        temp_cert.flush()
        del pem
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(temp_cert.name)
        return ssl_ctx

def get_pinned_cert_hash(pem):
    """Get the public key from the private one and output the base64
    encoded sha256 hash that curl needs to pin a certificate"""
    der = get_pubkey_as_der(pem)
    digest = get_pubkey_digest(der)
    return str(base64.b64encode(digest), "utf-8")

def create_self_signed_cert():
    """Create a new self-signed cerificate"""
    with tempfile.NamedTemporaryFile() as temp_cert:
        with subprocess.Popen(
                ['openssl', 'req', '-new', '-x509', '-days', '365',
                '-nodes', '-out', temp_cert.name, '-keyout', temp_cert.name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE) as p:
            p.stdin.write(b"\n"*10)
        return open(temp_cert.name,'br').read()

def get_ssl_context_from_settings(settings):    
    if settings['ssl'] is not False:
        if settings['ssl'] is None:
            # Create self-signed certificate for one use:
            log.warn("No SSL certificate provided, creating a new self-signed certificate for this session")
            cert = create_self_signed_cert()
            # Always pin the certificate if we are using self-signed cert:
            settings['pin'] = True
        else:
            # Use pre-generated certificate file:
            with open(settings['ssl'], 'br') as cert_file:
                cert = decrypt_cert_if_necessary(cert_file.read())
        ssl_ctx = create_ssl_ctx(cert)
        settings['ssl_hash'] = get_pinned_cert_hash(cert)
        log.info("SSL certificate loaded")
    else:
        ssl_ctx = None
    return ssl_ctx
