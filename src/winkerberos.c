/*
 * Copyright 2016 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kerberos_sspi.h"

#if PY_MAJOR_VERSION >= 3
#define PyInt_FromLong PyLong_FromLong
#define PyString_FromString PyUnicode_FromString
#define PyCObject_Check PyCapsule_CheckExact
#define PyCObject_FromVoidPtr(cobj, destr) PyCapsule_New(cobj, NULL, destr)
#define PyCObject_AsVoidPtr(self) PyCapsule_GetPointer(self, NULL)
#endif

PyDoc_STRVAR(winkerberos_documentation,
"A native Kerberos SSPI client implementation.\n"
"\n"
"This module mimics the client API of pykerberos to implement\n"
"Kerberos SSPI authentication on Microsoft Windows.");

/* Note - also defined extern in kerberos_sspi.c */
PyObject* KrbError;

static VOID
#if PY_MAJOR_VERSION >=3
destroy_sspi_client(PyObject* obj) {
    sspi_client_state* state = PyCapsule_GetPointer(obj, NULL);
#else
destroy_sspi_client(VOID* obj) {
    sspi_client_state* state = (sspi_client_state*)obj;
#endif
    if (state) {
        destroy_sspi_client_state(state);
        free(state);
    }
}

PyDoc_STRVAR(sspi_client_init_doc,
"authGSSClientInit(service, principal=None, gssflags="
"GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG, user=None, domain=None,"
" password=None)\n"
"\n"
"Initializes a context for Kerberos SSPI client side authentication with\n"
"the given service principal.\n"
"\n"
"The following flags are available (with SSPI mapping):\n"
"GSS_C_DELEG_FLAG    (ISC_REQ_DELEG)\n"
"GSS_C_MUTUAL_FLAG   (ISC_REQ_MUTUAL_AUTH)\n"
"GSS_C_REPLAY_FLAG   (ISC_REQ_REPLAY_DETECT)\n"
"GSS_C_SEQUENCE_FLAG (ISC_REQ_SEQUENCE_DETECT)\n"
"GSS_C_CONF_FLAG     (ISC_REQ_CONFIDENTIALITY)\n"
"GSS_C_INTEG_FLAG    (ISC_REQ_INTEGRITY)\n"
"\n"
"The following flags are *not* available as they have no mapping in SSPI:\n"
"GSS_C_ANON_FLAG\n"
"GSS_C_PROT_READY_FLAG\n"
"GSS_C_TRANS_FLAG\n"
"\n"
"Parameters: service: A string containing the service principal in \n"
"                     RFC-2078 format (service@hostname) or SPN\n"
"                     format (service/hostname or service/hostname@REALM).\n"
"            principal: An optional string containing the user principal\n"
"                       name in the format 'user@realm'.\n"
"            gssflags: An optional integer used to set GSS flags. Defaults\n"
"                      to GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG.\n"
"            user: An optional string that contains the name of the user\n"
"                  whose credentials should be used for authentication.\n"
"            domain: An optional string that contains the domain or\n"
"                    workgroup name for `user`.\n"
"            password: An optional string that contains the password for\n"
"                      `user` in `domain`.\n"
"\n"
"Returns: A tuple of (result, context) where result is AUTH_GSS_COMPLETE\n"
"         and context is an opaque value passed in subsequent function calls.");

static PyObject*
sspi_client_init(PyObject* self, PyObject* args, PyObject* kw) {
    sspi_client_state* state;
    PyObject* pyctx = NULL;
    SEC_CHAR* service;
    SEC_CHAR* principal = NULL;
    LONG flags = ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT;
    SEC_CHAR* user = NULL;
    SEC_CHAR* domain = NULL;
    SEC_CHAR* password = NULL;
    INT result = 0;
    static SEC_CHAR* keywords[] = {
        "service", "principal", "gssflags", "user", "domain", "password", NULL};

    if (!PyArg_ParseTupleAndKeywords(args,
                                     kw,
                                     "s|zlzzz",
                                     keywords,
                                     &service,
                                     &principal,
                                     &flags,
                                     &user,
                                     &domain,
                                     &password)) {
        return NULL;
    }
    if (flags < 0) {
        PyErr_SetString(PyExc_ValueError, "gss_flags must be >= 0");
        return NULL;
    }

    state = (sspi_client_state*)malloc(sizeof(sspi_client_state));
    if (state == NULL) {
        return PyErr_NoMemory();
    }

    pyctx = PyCObject_FromVoidPtr(state, &destroy_sspi_client);
    if (pyctx == NULL) {
        free(state);
        return NULL;
    }

    result = auth_sspi_client_init(
        service, principal, (ULONG)flags, user, domain, password, state);
    if (result == AUTH_GSS_ERROR) {
        Py_DECREF(pyctx);
        return NULL;
    }

    return Py_BuildValue("(iN)", result, pyctx);
}

PyDoc_STRVAR(sspi_client_clean_doc,
"authGSSClientClean(context)\n"
"\n"
"Destroys the context. This function is provided for API compatibility with\n"
"pykerberos but does nothing. The context object destroys itself when it\n"
"is reclaimed.\n"
"\n"
"Parameters: context: The context object returned by authGSSClientInit.\n"
"\n"
"Returns: AUTH_GSS_COMPLETE");

static PyObject*
sspi_client_clean(PyObject* self, PyObject* args) {
    /* Do nothing. For compatibility with pykerberos only. */
    return Py_BuildValue("i", AUTH_GSS_COMPLETE);
}

PyDoc_STRVAR(sspi_client_step_doc,
"authGSSClientStep(context, challenge)\n"
"\n"
"Executes a single Kerberos SSPI client step using the supplied server "
"challenge.\n"
"\n"
"Parameters: context: The context object returned by authGSSClientInit.\n"
"            challenge: A string containing the base64 encoded server\n"
"            challenge. Ignored for the first step (pass the empty string).\n"
"\n"
"Returns: AUTH_GSS_CONTINUE or AUTH_GSS_COMPLETE");

static PyObject*
sspi_client_step(PyObject* self, PyObject* args) {
    sspi_client_state* state;
    PyObject* pyctx;
    SEC_CHAR* challenge = NULL;
    INT result = 0;

    if (!PyArg_ParseTuple(args, "Os", &pyctx, &challenge)) {
        return NULL;
    }

    if (!PyCObject_Check(pyctx)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (sspi_client_state*)PyCObject_AsVoidPtr(pyctx);
    if (state == NULL) {
        return NULL;
    }

    result = auth_sspi_client_step(state, challenge);
    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("i", result);
}

PyDoc_STRVAR(sspi_client_response_doc,
"authGSSClientResponse(context)\n"
"\n"
"Get the response to the last successful client operation.\n"
"\n"
"Parameters: context: The context object returned by authGSSClientInit.\n"
"\n"
"Returns: A base64 encoded string to return to the server.");

static PyObject*
sspi_client_response(PyObject* self, PyObject* args) {
    sspi_client_state* state;
    PyObject* pyctx;

    if (!PyArg_ParseTuple(args, "O", &pyctx)) {
        return NULL;
    }

    if (!PyCObject_Check(pyctx)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (sspi_client_state*)PyCObject_AsVoidPtr(pyctx);
    if (state == NULL) {
        return NULL;
    }

    return Py_BuildValue("s", state->response);
}

PyDoc_STRVAR(sspi_client_username_doc,
"authGSSClientUsername(context)\n"
"\n"
"Get the user name of the authenticated principal. Will only succeed after\n"
"authentication is complete.\n"
"\n"
"Parameters: context: The context object returned by authGSSClientInit.\n"
"\n"
"Returns: A string containing the username.");

static PyObject*
sspi_client_username(PyObject* self, PyObject* args) {
    sspi_client_state* state;
    PyObject* pyctx;

    if (!PyArg_ParseTuple(args, "O", &pyctx)) {
        return NULL;
    }

    if (!PyCObject_Check(pyctx)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (sspi_client_state*)PyCObject_AsVoidPtr(pyctx);
    if (state == NULL) {
        return NULL;
    }

    return Py_BuildValue("s", state->username);
}

PyDoc_STRVAR(sspi_client_unwrap_doc,
"authGSSClientUnwrap(context, challenge)\n"
"\n"
"Execute the client side DecryptMessage (GSSAPI Unwrap) operation.\n"
"\n"
"Parameters: context: The context object returned by authGSSClientInit.\n"
"            challenge: A string containing the base64 encoded server\n"
"            challenge.\n"
"\n"
"Returns: AUTH_GSS_COMPLETE");

static PyObject*
sspi_client_unwrap(PyObject* self, PyObject* args) {
    sspi_client_state* state;
    PyObject* pyctx;
    SEC_CHAR* challenge;
    INT result;

    if (!PyArg_ParseTuple(args, "Os", &pyctx, &challenge)) {
        return NULL;
    }

    if (!PyCObject_Check(pyctx)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (sspi_client_state*)PyCObject_AsVoidPtr(pyctx);
    if (state == NULL) {
        return NULL;
    }

    result = auth_sspi_client_unwrap(state, challenge);
    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("i", result);
}

PyDoc_STRVAR(sspi_client_wrap_doc,
"authGSSClientWrap(context, data, user=None)\n"
"\n"
"Execute the client side EncryptMessage (GSSAPI Wrap) operation.\n"
"\n"
"Parameters: context: The context object returned by authGSSClientInit.\n"
"            data: The result of calling authGSSClientResponse after\n"
"            authGSSClientUnwrap.\n"
"            user: The user to authenticate.\n"
"\n"
"Returns: AUTH_GSS_COMPLETE");

static PyObject*
sspi_client_wrap(PyObject* self, PyObject* args) {
    sspi_client_state* state;
    PyObject* pyctx;
    SEC_CHAR* data;
    SEC_CHAR* user = NULL;
    INT result;

    if (!PyArg_ParseTuple(args, "Os|z", &pyctx, &data, &user)) {
        return NULL;
    }

    if (!PyCObject_Check(pyctx)) {
        PyErr_SetString(PyExc_TypeError, "Expected a context object");
        return NULL;
    }

    state = (sspi_client_state*)PyCObject_AsVoidPtr(pyctx);
    if (state == NULL) {
        return NULL;
    }

    result = auth_sspi_client_wrap(state, data, user);
    if (result == AUTH_GSS_ERROR) {
        return NULL;
    }

    return Py_BuildValue("i", result);
}

static PyMethodDef WinKerberosClientMethods[] = {
    {"authGSSClientInit", (PyCFunction)sspi_client_init,
     METH_VARARGS | METH_KEYWORDS, sspi_client_init_doc},
    {"authGSSClientClean", sspi_client_clean,
     METH_VARARGS, sspi_client_clean_doc},
    {"authGSSClientStep", sspi_client_step,
     METH_VARARGS, sspi_client_step_doc},
    {"authGSSClientResponse", sspi_client_response,
     METH_VARARGS, sspi_client_response_doc},
    {"authGSSClientUsername", sspi_client_username,
     METH_VARARGS, sspi_client_username_doc},
    {"authGSSClientUnwrap", sspi_client_unwrap,
     METH_VARARGS, sspi_client_unwrap_doc},
    {"authGSSClientWrap", sspi_client_wrap,
     METH_VARARGS, sspi_client_wrap_doc},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
#define INITERROR return NULL

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "winkerberos",
    winkerberos_documentation,
    -1,
    WinKerberosClientMethods,
    NULL,
    NULL,
    NULL,
    NULL,
};

PyMODINIT_FUNC
PyInit_winkerberos(VOID)
#else
#define INITERROR return
PyMODINIT_FUNC
initwinkerberos(VOID)
#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject* module = PyModule_Create(&moduledef);
#else
    PyObject* module = Py_InitModule3(
        "winkerberos",
        WinKerberosClientMethods,
        winkerberos_documentation);
#endif
    if (module == NULL) {
        INITERROR;
    }

    KrbError = PyErr_NewException(
        "winkerberos.KrbError", NULL, NULL);
    if (KrbError == NULL) {
        Py_DECREF(module);
        INITERROR;
    }
    Py_INCREF(KrbError);
    
    if (PyModule_AddObject(module,
                           "KrbError",
                           KrbError) ||
        PyModule_AddObject(module,
                           "AUTH_GSS_COMPLETE",
                           PyInt_FromLong(AUTH_GSS_COMPLETE)) ||
        PyModule_AddObject(module,
                           "AUTH_GSS_CONTINUE",
                           PyInt_FromLong(AUTH_GSS_CONTINUE)) ||
        PyModule_AddObject(module,
                           "GSS_C_DELEG_FLAG",
                           PyInt_FromLong(ISC_REQ_DELEGATE)) ||
        PyModule_AddObject(module,
                           "GSS_C_MUTUAL_FLAG",
                           PyInt_FromLong(ISC_REQ_MUTUAL_AUTH)) ||
        PyModule_AddObject(module,
                           "GSS_C_REPLAY_FLAG",
                           PyInt_FromLong(ISC_REQ_REPLAY_DETECT)) ||
        PyModule_AddObject(module,
                           "GSS_C_SEQUENCE_FLAG",
                           PyInt_FromLong(ISC_REQ_SEQUENCE_DETECT)) ||
        PyModule_AddObject(module,
                           "GSS_C_CONF_FLAG",
                           PyInt_FromLong(ISC_REQ_CONFIDENTIALITY)) ||
        PyModule_AddObject(module,
                           "GSS_C_INTEG_FLAG",
                           PyInt_FromLong(ISC_REQ_INTEGRITY)) ||
        PyModule_AddObject(module,
                           "__version__",
                           PyString_FromString("0.1.0.dev0"))) {
        Py_DECREF(KrbError);
        Py_DECREF(module);
        INITERROR;
    }

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
