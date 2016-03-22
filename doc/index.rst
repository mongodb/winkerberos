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

This is a simplified example of a complete authentication session:

.. code-block:: pycon

    import winkerberos as kerberos

    def send_response_and_receive_challenge(response):
        # Your server communication code here...
        pass

    def authenticate_kerberos(service, user):
        # Initialize the context object.
        status, ctx = kerberos.authGSSClientInit(service)

        # GSSAPI is a "client first" algorithm. Send the first
        # "response" to the server and recieve its first
        # challenge.
        status = kerberos.authGSSClientStep(ctx, "")
        response = kerberos.authGSSClientResponse(ctx)
        challenge = send_response_and_receive_challenge(response)

        # Keep processing challenges and sending responses until
        # authGSSClientStep reports AUTH_GSS_COMPLETE.
        while status == kerberos.AUTH_GSS_CONTINUE:
            status = kerberos.authGSSClientStep(ctx, challenge)
            response = kerberos.authGSSClientResponse(ctx) or ''
            challenge = send_response_and_receive_challenge(response)

        # Decrypt the server's authentication challenge
        kerberos.authGSSClientUnwrap(ctx, challenge)
        data = kerberos.authGSSClientResponse(ctx)
        # Encrypt a response including the user to authenticate
        kerberos.authGSSClientWrap(ctx, data, user)
        response = kerberos.authGSSClientResponse(ctx)

        # Complete authentication.
        send_response_and_receive_challenge(response)

.. toctree::
   :hidden:

   winkerberos

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


About This Documentation
------------------------
This documentation is generated using the `Sphinx
<http://www.sphinx-doc.org/>`_ documentation generator. The source files
for the documentation are located in the *doc/* directory of the 
**WinKerberos** distribution. To generate the docs locally run the 
following command from the root directory of the **WinKerberos** source::

  python setup.py doc


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

