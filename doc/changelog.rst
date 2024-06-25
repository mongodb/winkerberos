Changelog
=========

Changes in Version 0.11.0
-------------------------

- Drop support for Python version 3.7.
- Add Secure Software Development Life Cycle automation to release process.
  GitHub Releases now include a Software Bill of Materials, and signature
  files corresponding to the distribution files released on PyPI.

Changes in Version 0.10.0
-------------------------

- Add support for Python 3.12.  Drop support for Python versions 2.7, 3.5, and 3.6.


Changes in Version 0.9.1
------------------------

- Add support for Python 3.11.


Changes in Version 0.9.0
------------------------

- Fix build in mingw-w64: ``MINGW_CHOST`` is specific to msys2 build and
  packaging environment. Instead, check ``sys.version`` which is available in
  any python env.  Also remove ``SecPkgContext_Bindings`` definition which has
  been added in ``mingw-w64`` headers.
- Allow ``channel_bindings=None`` for ``authGSSClientStep``.
- WinKerberos now requires Python 2.7 or 3.5+.

Changes in Version 0.8.0
------------------------

- WinKerberos now builds under MSYS2 using mingw-w64. Note
  that you can't use this support to build with python.org
  provided Pythons and mingw-w64. See `<https://bugs.python.org/issue25251>`_
  for a related discussion. Thanks go to Antoine Martin for the patch.
- Experimental server side API. Thanks go to Kacper Bostrom for the patch.

*Backward Breaking Changes*

- ``authGSSClientUsername`` has been renamed
  :func:`winkerberos.authGSSClientUserName` to match ccs-pykerberos.
- WinKerberos no longer supports Python 2.6 or Python 3.3.

Changes in Version 0.7.0
------------------------

- Added optional support for passing in Channel Binding Tokens (RFC 5929) into
  :func:`winkerberos.authGSSClientStep`. The binding token structure can be
  built using :func:`winkerberos.channelBindings` (see the example
  for more details). Thanks go to Jordan Borean for the patch.

Changes in Version 0.6.0
------------------------

- Added the ``mech_oid`` parameter to :func:`~winkerberos.authGSSClientInit`.
  Thanks go to Alexey Veklov for the patch.

Changes in Version 0.5.0
------------------------

- Added :func:`~winkerberos.authGSSClientResponseConf` and the ``protect``
  parameter to :func:`~winkerberos.authGSSClientWrap`.
- Fixed support for the ``principal`` parameter of
  :func:`~winkerberos.authGSSClientInit`, which had no effect in previous
  versions.
- Deprecated the :func:`~winkerberos.authGSSClientInit` parameters ``user``,
  ``domain``, and ``password``.
- Various improvements to Sphinx documentation builds.

Changes in Version 0.4.0
------------------------

- Added :exc:`~winkerberos.GSSError`, inheriting from
  :exc:`~winkerberos.KrbError`, for compatibility with pykerberos. WinKerberos
  now raises GSSError instead of KrbError. This change is backward compatible
  for all existing applications.

Changes in Version 0.3.0
------------------------

- Switched to InitializeSecurityContextW to better support unicode
  service principal names.

Changes in Version 0.2.0
------------------------

- The ``password`` parameter of :func:`~winkerberos.authGSSClientInit` can be a
  :class:`bytearray` or any other 8-bit string type that implements the buffer
  interface.
- Fixed an issue where :func:`~winkerberos.authGSSClientUsername` could raise
  :exc:`UnicodeDecodeError`.

Changes in Version 0.1.0
------------------------

This was the initial release of WinKerberos.
