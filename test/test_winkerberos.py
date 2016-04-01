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
import mmap
import os
import sys

if sys.version_info[:2] == (2, 6):
    import unittest2 as unittest
else:
    import unittest

sys.path[0:0] = [""]

import winkerberos as kerberos

_HAVE_PYMONGO = True
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
except ImportError:
    _HAVE_PYMONGO = False

_PY3 = sys.version_info[0] >= 3

# NOTE: Testing with non-ascii values will only work with python 3.x.
_HOST = os.environ.get('MONGODB_HOST', 'localhost')
_PORT = int(os.environ.get('MONGODB_PORT', 27017))
_SPN = os.environ.get('KERBEROS_SERVICE')
_PRINCIPAL = os.environ.get('KERBEROS_PRINCIPAL')
_UPN = os.environ.get('KERBEROS_UPN')
_USER = os.environ.get('KERBEROS_USER')
_DOMAIN = os.environ.get('KERBEROS_DOMAIN')
_PASSWORD = os.environ.get('KERBEROS_PASSWORD')


class TestWinKerberos(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _HAVE_PYMONGO:
            raise unittest.SkipTest("Could not import pymongo")
        if _SPN is None:
            raise unittest.SkipTest("KERBEROS_SERVICE is required")
        cls.client = MongoClient(_HOST, _PORT, connect=False, maxPoolSize=1)
        cls.db = cls.client['$external']
        try:
            cls.client.admin.command('ismaster')
        except ConnectionFailure:
            raise unittest.SkipTest("Could not connection to MongoDB")

    def authenticate(self,
                     service=_SPN,
                     principal=_PRINCIPAL,
                     flags=kerberos.GSS_C_MUTUAL_FLAG,
                     user=_USER,
                     domain=_DOMAIN,
                     password=_PASSWORD,
                     upn=_UPN):
            res, ctx = kerberos.authGSSClientInit(
                service, principal, flags, user, domain, password)
            res = kerberos.authGSSClientStep(ctx, "")
            payload = kerberos.authGSSClientResponse(ctx)
            response = self.db.command(
                'saslStart', mechanism='GSSAPI', payload=payload)
            while res == kerberos.AUTH_GSS_CONTINUE:
                res = kerberos.authGSSClientStep(ctx, response['payload'])
                payload = kerberos.authGSSClientResponse(ctx) or ''
                response = self.db.command(
                   'saslContinue',
                   conversationId=response['conversationId'],
                   payload=payload)
            kerberos.authGSSClientUnwrap(ctx, response['payload'])
            kerberos.authGSSClientWrap(ctx,
                                       kerberos.authGSSClientResponse(ctx),
                                       upn)
            response = self.db.command(
               'saslContinue',
               conversationId=response['conversationId'],
               payload=kerberos.authGSSClientResponse(ctx))
            self.assertTrue(response['done'])

    def test_authenticate(self):
        res, ctx = kerberos.authGSSClientInit(
            _SPN,
            _PRINCIPAL,
            kerberos.GSS_C_MUTUAL_FLAG,
            _USER,
            _DOMAIN,
            _PASSWORD)
        self.assertEqual(res, kerberos.AUTH_GSS_COMPLETE)

        res = kerberos.authGSSClientStep(ctx, "")
        self.assertEqual(res, kerberos.AUTH_GSS_CONTINUE)

        payload = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(payload, str)

        response = self.db.command(
            'saslStart', mechanism='GSSAPI', payload=payload)
        while res == kerberos.AUTH_GSS_CONTINUE:
            res = kerberos.authGSSClientStep(ctx, response['payload'])
            payload = kerberos.authGSSClientResponse(ctx) or ''
            response = self.db.command(
               'saslContinue',
               conversationId=response['conversationId'],
               payload=payload)

        res = kerberos.authGSSClientUnwrap(ctx, response['payload'])
        self.assertEqual(res, 1)

        unwrapped = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(unwrapped, str)

        # Try just rewrapping (no user)
        res = kerberos.authGSSClientWrap(ctx, unwrapped)
        self.assertEqual(res, 1)

        wrapped = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(wrapped, str)

        # Actually complete authentication
        res = kerberos.authGSSClientWrap(ctx, unwrapped, _UPN)
        self.assertEqual(res, 1)

        wrapped = kerberos.authGSSClientResponse(ctx)
        self.assertIsInstance(wrapped, str)

        response = self.db.command(
           'saslContinue',
           conversationId=response['conversationId'],
           payload=wrapped)
        self.assertTrue(response['done'])

        self.assertIsInstance(kerberos.authGSSClientUsername(ctx), str)

    def test_uninitialized_context(self):
        res, ctx = kerberos.authGSSClientInit(
            _SPN,
            _PRINCIPAL,
            kerberos.GSS_C_MUTUAL_FLAG,
            _USER,
            _DOMAIN,
            _PASSWORD)
        self.assertEqual(res, kerberos.AUTH_GSS_COMPLETE)

        self.assertIsNone(kerberos.authGSSClientResponse(ctx))
        self.assertIsNone(kerberos.authGSSClientUsername(ctx))
        self.assertRaises(
            kerberos.KrbError, kerberos.authGSSClientUnwrap, ctx, "foobar")
        self.assertRaises(
            kerberos.KrbError, kerberos.authGSSClientWrap, ctx, "foobar")

    def test_arg_parsing(self):

        self.assertRaises(TypeError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          bytearray())
        self.assertRaises(TypeError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          u"foo",
                          0,
                          bytearray())
        self.assertRaises(TypeError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          u"foo",
                          0,
                          u"foo",
                          bytearray())
        self.assertRaises(TypeError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          u"foo",
                          0,
                          u"foo",
                          u"foo",
                          {})

        self.assertRaises(ValueError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          u"fo\0")
        self.assertRaises(ValueError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          u"foo",
                          0,
                          u"f0\0")
        self.assertRaises(ValueError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          u"foo",
                          0,
                          u"foo",
                          u"fo\0")
        self.assertRaises(ValueError,
                          kerberos.authGSSClientInit,
                          u"foo",
                          u"foo",
                          0,
                          u"foo",
                          u"foo",
                          u"fo\0")

        if _PY3:
            self.assertRaises(TypeError,
                              kerberos.authGSSClientInit,
                              "foo",
                              b"foo")
            self.assertRaises(TypeError,
                              kerberos.authGSSClientInit,
                              "foo",
                              "foo",
                              0,
                              b"foo")
            self.assertRaises(TypeError,
                              kerberos.authGSSClientInit,
                              "foo",
                              "foo",
                              0,
                              "foo",
                              b"foo")

    def test_password_buffer(self):
        password = bytearray(_PASSWORD, "utf8")
        try:
            self.authenticate(password=password)
        except kerberos.KrbError as exc:
            self.fail("Failed bytearray: %s" % (str(exc),))

        # memoryview doesn't exist in python 2.6
        if sys.version_info[:2] >= (2, 7):
            try:
                self.authenticate(password=memoryview(password))
            except kerberos.KrbError as exc:
                self.fail("Failed memoryview: %s" % (str(exc),))

        # mmap.mmap and array.array only expose the
        # buffer interface in python 3.x
        if _PY3:
            mm = mmap.mmap(-1, len(password))
            mm.write(_PASSWORD.encode("utf8"))
            mm.seek(0)
            try:
                self.authenticate(password=mm)
            except kerberos.KrbError as exc:
                self.fail("Failed map.map: %s" % (str(exc),))

            # Note that only ascii and utf8 strings are supported, so
            # 'u' with a unicode object won't work. Unicode objects
            # must be encoded utf8 first.
            try:
                self.authenticate(password=array.array('b', password))
            except kerberos.KrbError as exc:
                self.fail("Failed array.array: %s" % (str(exc),))

