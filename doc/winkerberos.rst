:mod:`winkerberos`
==================

.. automodule:: winkerberos
   :synopsis: A native Kerberos SSPI client implementation.

   .. autofunction:: authGSSClientInit
   .. autofunction:: authGSSClientStep
   .. autofunction:: authGSSClientResponse
   .. autofunction:: authGSSClientResponseConf
   .. autofunction:: authGSSClientUserName
   .. autofunction:: authGSSClientUnwrap
   .. autofunction:: authGSSClientWrap
   .. autofunction:: authGSSClientClean
   .. autofunction:: channelBindings
   .. autofunction:: authGSSServerInit
   .. autofunction:: authGSSServerStep
   .. autofunction:: authGSSServerResponse
   .. autofunction:: authGSSServerUserName
   .. autofunction:: authGSSServerClean
   .. autoexception:: KrbError
   .. autoexception:: GSSError
   .. data:: AUTH_GSS_COMPLETE
   .. data:: AUTH_GSS_CONTINUE
   .. data:: GSS_C_DELEG_FLAG
   .. data:: GSS_C_MUTUAL_FLAG
   .. data:: GSS_C_REPLAY_FLAG
   .. data:: GSS_C_SEQUENCE_FLAG
   .. data:: GSS_C_CONF_FLAG
   .. data:: GSS_C_INTEG_FLAG
   .. data:: GSS_C_AF_UNSPEC
   .. data:: GSS_MECH_OID_KRB5
   .. data:: GSS_MECH_OID_SPNEGO
   .. data:: __version__
