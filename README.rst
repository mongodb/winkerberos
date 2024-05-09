===========
WinKerberos
===========
:Info: See `github <https://github.com/mongodb-labs/winkerberos>`_ for the latest source.
:Author: Bernie Hackett <bernie@mongodb.com>

About
=====

A native Kerberos client implementation for Python on Windows. This module
mimics the API of `pykerberos <https://pypi.python.org/pypi/pykerberos>`_ to
implement Kerberos authentication with Microsoft's Security Support Provider
Interface (SSPI). It supports Python 3.8+.

Installation
============

WinKerberos is in the `Python Package Index (pypi)
<https://pypi.python.org/pypi/winkerberos>`_. Use `pip
<https://pypi.python.org/pypi/pip>`_ to install it::

  python -m pip install winkerberos

WinKerberos requires Windows 7 / Windows Server 2008 R2 or newer.

Building and installing from source
===================================

You must have the correct version of VC++ installed for your version of
Python:

- Python 3.8+ - Visual Studio 2015+ (Any version)

Once you have the required compiler installed, run the following command from
the root directory of the WinKerberos source::

    pip install .

Building HTML documentation
===========================

First install `Sphinx <https://pypi.python.org/pypi/Sphinx>`_::

    python -m pip install Sphinx

Then run the following command from the root directory of the WinKerberos
source::

    pip install -e .
    python -m sphinx -b html doc doc/_build


Examples
========

This is a simplified example of a complete authentication session
following RFC-4752, section 3.1:

.. code-block:: python

    import winkerberos as kerberos


    def send_response_and_receive_challenge(response):
        # Your server communication code here...
        pass


    def authenticate_kerberos(service, user, channel_bindings=None):
        # Initialize the context object with a service principal.
        status, ctx = kerberos.authGSSClientInit(service)

        # GSSAPI is a "client goes first" SASL mechanism. Send the
        # first "response" to the server and receive its first
        # challenge.
        if channel_bindings is not None:
            status = kerberos.authGSSClientStep(ctx, "", channel_bindings=channel_bindings)
        else:
            status = kerberos.authGSSClientStep(ctx, "")
        response = kerberos.authGSSClientResponse(ctx)
        challenge = send_response_and_receive_challenge(response)

        # Keep processing challenges and sending responses until
        # authGSSClientStep reports AUTH_GSS_COMPLETE.
        while status == kerberos.AUTH_GSS_CONTINUE:
            if channel_bindings is not None:
                status = kerberos.authGSSClientStep(
                    ctx, challenge, channel_bindings=channel_bindings
                )
            else:
                status = kerberos.authGSSClientStep(ctx, challenge)

            response = kerberos.authGSSClientResponse(ctx) or ""
            challenge = send_response_and_receive_challenge(response)

        # Decrypt the server's last challenge
        kerberos.authGSSClientUnwrap(ctx, challenge)
        data = kerberos.authGSSClientResponse(ctx)
        # Encrypt a response including the user principal to authorize.
        kerberos.authGSSClientWrap(ctx, data, user)
        response = kerberos.authGSSClientResponse(ctx)

        # Complete authentication.
        send_response_and_receive_challenge(response)

Channel bindings can be generated with help from the cryptography_ module. See
`<https://tools.ietf.org/html/rfc5929#section-4.1>`_ for the rules regarding
hash algorithm choice:

.. code-block:: python

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes


    def channel_bindings(ssl_socket):
        server_certificate = ssl_socket.getpeercert(True)
        cert = x509.load_der_x509_certificate(server_certificate, default_backend())
        hash_algorithm = cert.signature_hash_algorithm
        if hash_algorithm.name in ("md5", "sha1"):
            digest = hashes.Hash(hashes.SHA256(), default_backend())
        else:
            digest = hashes.Hash(hash_algorithm, default_backend())
        digest.update(server_certificate)
        application_data = b"tls-server-end-point:" + digest.finalize()
        return kerberos.channelBindings(application_data=application_data)


.. _cryptography: https://pypi.python.org/pypi/cryptography

Viewing API Documentation without Sphinx
========================================

Use the help function in the python interactive shell:

.. code-block:: pycon

    >>> import winkerberos
    >>> help(winkerberos)
