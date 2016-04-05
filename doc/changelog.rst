Changelog
=========

Changes in Verion 0.2.0
-----------------------

- The password parameter of :func:`~winkerberos.authGSSClientInit` can be a
  :class:`bytearray` or any other 8-bit string type that implements the buffer
  interface.
- Fixed an issue where :func:`~winkerberos.authGSSClientUsername` could raise
  :exc:`UnicodeDecodeError`.

Changes in Version 0.1.0
------------------------

This was the initial release of WinKerberos.
