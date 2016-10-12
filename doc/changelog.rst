Changelog
=========

Changes in Version 0.5.0
------------------------

- Fixed support for the `principal` parameter of
  :func:`~winkerberos.authGSSClientInit`, which had no effect in previous
  versions.
- Deprecated the :func:`~winkerberos.authGSSClientInit` parameters `user`,
  `domain`, and `password`.
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

- The `password` parameter of :func:`~winkerberos.authGSSClientInit` can be a
  :class:`bytearray` or any other 8-bit string type that implements the buffer
  interface.
- Fixed an issue where :func:`~winkerberos.authGSSClientUsername` could raise
  :exc:`UnicodeDecodeError`.

Changes in Version 0.1.0
------------------------

This was the initial release of WinKerberos.
