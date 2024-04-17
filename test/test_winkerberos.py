# Copyright 2016 MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import array
import base64
import mmap
import os
import sys
import unittest

sys.path[0:0] = [""]

import winkerberos as kerberos  # noqa: E402

_HAVE_PYMONGO = True
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
except ImportError:
    _HAVE_PYMONGO = False

_HOST = os.environ.get("MONGODB_HOST", "localhost")
_PORT = int(os.environ.get("MONGODB_PORT", 27017))
_SPN = os.environ.get("KERBEROS_SERVICE")
_PRINCIPAL = os.environ.get("KERBEROS_PRINCIPAL")
_UPN = os.environ.get("KERBEROS_UPN")
_USER = os.environ.get("KERBEROS_USER")
_DOMAIN = os.environ.get("KERBEROS_DOMAIN")
_PASSWORD = os.environ.get("KERBEROS_PASSWORD")


class TestWinKerberos(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HAVE_PYMONGO:
            raise unittest.SkipTest("Could not import pymongo")
        if _SPN is None:
            raise unittest.SkipTest("KERBEROS_SERVICE is required")
        cls.client = MongoClient(_HOST, _PORT, connect=False, maxPoolSize=1)
        cls.db = cls.client["$external"]
        try:
            cls.client.admin.command("ismaster")
        except ConnectionFailure:
            raise unittest.SkipTest("Could not connection to MongoDB")

    def authenticate(
        self,
        service=_SPN,
        principal=None,
        flags=kerberos.GSS_C_MUTUAL_FLAG,
        user=_USER,
        domain=_DOMAIN,
        password=_PASSWORD,
        mech_oid=kerberos.GSS_MECH_OID_KRB5,
        upn=_UPN,
        protect=0,
    ):
        res, ctx = kerberos.authGSSClientInit(
            service, principal, flags, user, domain, password, mech_oid
        )
        res = kerberos.authGSSClientStep(ctx, "")
        payload = kerberos.authGSSClientResponse(ctx)
        response = self.db.command("saslStart", mechanism="GSSAPI", payload=payload)
        while res == kerberos.AUTH_GSS_CONTINUE:
            res = kerberos.authGSSClientStep(ctx, response["payload"])
            payload = kerberos.authGSSClientResponse(ctx) or ""
            response = self.db.command(
                "saslContinue",
                conversationId=response["conversationId"],
                payload=payload,
            )
        kerberos.authGSSClientUnwrap(ctx, response["payload"])
        kerberos.authGSSClientWrap(
            ctx, kerberos.authGSSClientResponse(ctx), upn, protect
        )
        response = self.db.command(
            "saslContinue",
            conversationId=response["conversationId"],
            payload=kerberos.authGSSClientResponse(ctx),
        )
        self.assertTrue(response["done"])

    def test_authenticate(self):
        res, ctx = kerberos.authGSSClientInit(
            _SPN, None, kerberos.GSS_C_MUTUAL_FLAG, _USER, _DOMAIN, _PASSWORD
        )
        self.assertEqual(res, kerberos.AUTH_GSS_COMPLETE)

        res = kerberos.authGSSClientStep(ctx, "", channel_bindings=None)
        self.assertEqual(res, kerberos.AUTH_GSS_CONTINUE)

        payload = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(payload, str)

        response = self.db.command("saslStart", mechanism="GSSAPI", payload=payload)
        while res == kerberos.AUTH_GSS_CONTINUE:
            res = kerberos.authGSSClientStep(ctx, response["payload"])
            payload = kerberos.authGSSClientResponse(ctx) or ""
            response = self.db.command(
                "saslContinue",
                conversationId=response["conversationId"],
                payload=payload,
            )

        res = kerberos.authGSSClientUnwrap(ctx, response["payload"])
        self.assertEqual(res, 1)

        unwrapped = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(unwrapped, str)
        self.assertIsInstance(kerberos.authGSSClientResponseConf(ctx), int)

        # RFC-4752
        challenge_bytes = base64.standard_b64decode(unwrapped)
        self.assertEqual(4, len(challenge_bytes))

        # Manually create an authorization message and encrypt it. This
        # is the "no security layer" message as detailed in RFC-4752,
        # section 3.1, final paragraph. This is also the message created
        # by calling authGSSClientWrap with the "user" option.
        msg = base64.standard_b64encode(
            b"\x01\x00\x00\x00" + _UPN.encode("utf8")
        ).decode("utf8")
        res = kerberos.authGSSClientWrap(ctx, msg)
        self.assertEqual(res, 1)

        custom = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(custom, str)

        # Wrap using unwrapped and user principal.
        res = kerberos.authGSSClientWrap(ctx, unwrapped, _UPN)
        self.assertEqual(res, 1)

        wrapped = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(wrapped, str)

        # Actually complete authentication, using our custom message.
        response = self.db.command(
            "saslContinue", conversationId=response["conversationId"], payload=custom
        )
        self.assertTrue(response["done"])

        self.assertIsInstance(kerberos.authGSSClientUserName(ctx), str)

    def test_uninitialized_context(self):
        res, ctx = kerberos.authGSSClientInit(
            _SPN, None, kerberos.GSS_C_MUTUAL_FLAG, _USER, _DOMAIN, _PASSWORD
        )
        self.assertEqual(res, kerberos.AUTH_GSS_COMPLETE)

        self.assertIsNone(kerberos.authGSSClientResponse(ctx))
        self.assertIsNone(kerberos.authGSSClientUserName(ctx))
        self.assertRaises(
            kerberos.GSSError, kerberos.authGSSClientUnwrap, ctx, "foobar"
        )
        self.assertRaises(kerberos.GSSError, kerberos.authGSSClientWrap, ctx, "foobar")

    def test_arg_parsing(self):
        self.assertRaises(TypeError, kerberos.authGSSClientInit, None)
        self.assertRaises(
            TypeError, kerberos.authGSSClientInit, "foo", "foo", 0, bytearray()
        )
        self.assertRaises(
            TypeError, kerberos.authGSSClientInit, "foo", "foo", 0, "foo", bytearray()
        )
        self.assertRaises(
            TypeError, kerberos.authGSSClientInit, "foo", "foo", 0, "foo", "foo", {}
        )

        self.assertRaises(ValueError, kerberos.authGSSClientInit, "foo", "fo\0")
        self.assertRaises(
            ValueError, kerberos.authGSSClientInit, "foo", "foo", 0, "f0\0"
        )
        self.assertRaises(
            ValueError, kerberos.authGSSClientInit, "foo", "foo", 0, "foo", "fo\0"
        )
        self.assertRaises(
            ValueError,
            kerberos.authGSSClientInit,
            "foo",
            "foo",
            0,
            "foo",
            "foo",
            "fo\0",
        )

        self.assertRaises(
            TypeError, kerberos.authGSSClientInit, "foo", "foo", 0, b"foo"
        )
        self.assertRaises(
            TypeError, kerberos.authGSSClientInit, "foo", "foo", 0, "foo", b"foo"
        )

    def test_password_buffer(self):
        password = bytearray(_PASSWORD, "utf8")
        try:
            self.authenticate(password=password)
        except kerberos.GSSError as exc:
            self.fail("Failed bytearray: {}".format(str(exc)))

        try:
            self.authenticate(password=memoryview(password))
        except kerberos.GSSError as exc:
            self.fail("Failed memoryview: {}".format(str(exc)))

        mm = mmap.mmap(-1, len(password))
        mm.write(_PASSWORD.encode("utf8"))
        mm.seek(0)
        try:
            self.authenticate(password=mm)
        except kerberos.GSSError as exc:
            self.fail("Failed map.map: {}".format(str(exc)))

        # Note that only ascii and utf8 strings are supported, so
        # 'u' with a unicode object won't work. Unicode objects
        # must be encoded utf8 first.
        try:
            self.authenticate(password=array.array("b", password))
        except kerberos.GSSError as exc:
            self.fail("Failed array.array: {}".format(str(exc)))

    def test_principal(self):
        if _PRINCIPAL is None:
            raise unittest.SkipTest("Must set KERBEROS_PRINCIPAL to test")
        try:
            self.authenticate(
                principal=_PRINCIPAL, user=None, domain=None, password=None
            )
        except kerberos.GSSError as exc:
            self.fail("Failed testing principal: {}".format(str(exc)))

        encoded = bytearray(_PRINCIPAL, "utf8")
        # No error.
        self.authenticate(principal=encoded, user=None, domain=None, password=None)

        # No error. For backward compatibility, the user parameter takes
        # precedence.
        self.authenticate(principal="somebogus@user:pass")

        # Again, the user parameter takes precedence.
        self.assertRaises(
            kerberos.GSSError,
            self.authenticate,
            principal=_PRINCIPAL,
            user="somebogus",
            domain="user",
            password="pass",
        )

    def test_confidentiality(self):
        # No error.
        self.authenticate(
            flags=kerberos.GSS_C_MUTUAL_FLAG | kerberos.GSS_C_CONF_FLAG, protect=1
        )
        self.assertRaises(
            kerberos.GSSError,
            self.authenticate,
            flags=kerberos.GSS_C_MUTUAL_FLAG,
            protect=1,
        )

    def test_mech_oid(self):
        # No error.
        self.authenticate(mech_oid=kerberos.GSS_MECH_OID_KRB5)
        # No error here either, since the two sides
        # negotiate kerberos automatically.
        self.authenticate(mech_oid=kerberos.GSS_MECH_OID_SPNEGO)

    def test_exception_hierarchy(self):
        self.assertIsInstance(kerberos.KrbError(), Exception)
        self.assertIsInstance(kerberos.GSSError(), kerberos.KrbError)
