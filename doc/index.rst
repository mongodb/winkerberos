WinKerberos |release|
=====================

About
-----
**WinKerberos** is a native Kerberos SSPI client implementation. It mimics the
client API of `pykerberos <https://pypi.python.org/pypi/pykerberos>`_ to
implement Kerberos SSPI authentication on Microsoft Windows. The source is
`available on github <https://github.com/mongodb-labs/winkerberos>`_.

Documentation
-------------

:doc:`winkerberos`
  Full API documentation for the winkerberos module.

Installation
------------

WinKerberos is in the `Python Package Index (pypi)
<https://pypi.python.org/pypi/winkerberos>`_. Use `pip
<https://pypi.python.org/pypi/pip>`_ to install it::

  python -m pip install winkerberos

Building and installing from source
-----------------------------------

You must have the correct version of VC++ installed for your version of
Python:

- Python 2.6 - Visual Studio 2008 (Professional for 64bit)
- Python 2.7 - Visual Studio 2008 (Professional for 64bit)
- Python 3.3 - Visual Studio 2010 (Professional for 64bit)
- Python 3.4 - Visual Studio 2010 (Professional for 64bit)
- Python 3.5+ - Visual Studio 2015 (Any version)

The `Microsoft Visual C++ Compiler for Python 2.7
<https://www.microsoft.com/en-us/download/details.aspx?id=44266>`_ could also
be used to build for Python 2.6 and 2.7.

Once you have the required compiler installed, just run the following command::

    python setup.py install

Examples
--------

This is a simplified example of a complete authentication session
following RFC-4752, section 3.1:

.. code-block:: python

    import winkerberos as kerberos

    def get_channel_binding_struct(response):
        # This is 'tls-server-end-point:' + certificate hash of the server
        application_data = b'tls-server-end-point:D01402E0F16F30ED71B02B655AD71C7B0ADA73DE5FBD8134021A794FFA1EECE8'
        channel_bindings = kerberos.channelBindings(application_data=application_data)

        return channel_bindings

    def send_response_and_receive_challenge(response):
        # Your server communication code here...
        pass

    def authenticate_kerberos(service, user):
        # Initialize the context object with a service principal.
        status, ctx = kerberos.authGSSClientInit(service)

        # GSSAPI is a "client goes first" SASL mechanism. Send the
        # first "response" to the server and recieve its first
        # challenge.
        status = kerberos.authGSSClientStep(ctx, "")
        response = kerberos.authGSSClientResponse(ctx)
        challenge = send_response_and_receive_challenge(response)

        # OPTIONAL - Get Channel Bindings Struct to bind the TLS
        # channel to Kerberos Credentials. This is known as extended
        # protection in Microsoft. If this step isn't done then
        # no bindings are done
        # RFC5929 - Channel Bindings for TLS
        channel_bindings = get_channel_binding_struct(response)

        # Keep processing challenges and sending responses until
        # authGSSClientStep reports AUTH_GSS_COMPLETE.
        while status == kerberos.AUTH_GSS_CONTINUE:
            # When not wanting to pass in the Channel Bindings Struct
            status = kerberos.authGSSClientStep(ctx, challenge)

            # When passing in the Channel Bindings Struct
            status = kerberos.authGSSClientStep(ctx, challenge,
                    channel_bindings=channel_bindings)

            response = kerberos.authGSSClientResponse(ctx) or ''
            challenge = send_response_and_receive_challenge(response)

        # Decrypt the server's last challenge
        kerberos.authGSSClientUnwrap(ctx, challenge)
        data = kerberos.authGSSClientResponse(ctx)
        # Encrypt a response including the user principal to authorize.
        kerberos.authGSSClientWrap(ctx, data, user)
        response = kerberos.authGSSClientResponse(ctx)

        # Complete authentication.
        send_response_and_receive_challenge(response)

Issues
------
All issues should be reported (and can be tracked / voted for /
commented on) on the `github issues tracker
<https://github.com/mongodb-labs/winkerberos/issues>`_.

Contributing
------------
To contribute, fork the project on
`github <https://github.com/mongodb-labs/winkerberos>`_ and send a
pull request.

Changes
-------
See the :doc:`changelog` for a full list of changes to WinKerberos.

About This Documentation
------------------------
This documentation is generated using the `Sphinx
<http://www.sphinx-doc.org/>`_ documentation generator. The source files
for the documentation are located in the *doc/* directory of the 
**WinKerberos** distribution. To generate the docs locally install Sphinx::

  python -m pip install Sphinx

Then run the following command from the root directory of the **WinKerberos**
source::

  python setup.py doc

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. toctree::
   :hidden:

   changelog
   winkerberos

