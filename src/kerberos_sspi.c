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

extern PyObject* KrbError;

VOID
destroy_sspi_client_state(sspi_client_state* state) {
    if (state->haveCtx) {
        DeleteSecurityContext(&state->ctx);
        state->haveCtx = 0;
    }
    if (state->haveCred) {
        FreeCredentialsHandle(&state->cred);
        state->haveCred = 0;
    }
    if (state->spn != NULL) {
        free(state->spn);
        state->spn = NULL;
    }
    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }
    if (state->username != NULL) {
        free(state->username);
        state->username = NULL;
    }
}

static VOID
set_krberror(DWORD errCode, const SEC_CHAR* msg) {
    SEC_CHAR* err;
    DWORD status;
    DWORD flags = (FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_SYSTEM |
                   FORMAT_MESSAGE_IGNORE_INSERTS);
    status = FormatMessageA(flags,
                            NULL,
                            errCode,
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                            (LPTSTR)&err,
                            0,
                            NULL);
    if (status) {
        PyErr_Format(KrbError, "SSPI: %s: %s", msg, err);
        LocalFree(err);
    } else {
        PyErr_Format(KrbError, "SSPI: %s", msg);
    }
}

static SEC_CHAR*
base64_encode(const BYTE* value, DWORD vlen) {
    SEC_CHAR* out = NULL;
    DWORD len;
    /* Get the correct size for the out buffer. */
    if (CryptBinaryToStringA(value,
                             vlen,
                             CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
                             NULL,
                             &len)) {
        out = (SEC_CHAR*)malloc(sizeof(SEC_CHAR) * len);
        if (out) {
            /* Encode to the out buffer. */
            if (CryptBinaryToStringA(value,
                                     vlen,
                                     CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
                                     out,
                                     &len)) {
                return out;
            } else {
                free(out);
            }
        }
    }
    PyErr_Format(KrbError, "CryptBinaryToString failed.");
    return NULL;
}

static BYTE*
base64_decode(const SEC_CHAR* value, DWORD* rlen) {
    BYTE* out = NULL;
    /* Get the correct size for the out buffer. */
    if (CryptStringToBinaryA(value,
                             0,
                             CRYPT_STRING_BASE64,
                             NULL,
                             rlen,
                             NULL,
                             NULL)) {
        out = (BYTE*)malloc(sizeof(BYTE) * *rlen);
        if (out) {
            /* Decode to the out buffer. */
            if (CryptStringToBinaryA(value,
                                     0,
                                     CRYPT_STRING_BASE64,
                                     out,
                                     rlen,
                                     NULL,
                                     NULL)) {
                return out;
            } else {
                free(out);
            }
        }
    }
    PyErr_Format(KrbError, "CryptStringToBinary failed.");
    return NULL;
}

static VOID
set_uninitialized_context() {
    PyErr_SetString(KrbError,
                    "Uninitialized security context. You must use "
                    "authGSSClientStep to initialize the security "
                    "context before calling this function.");
}

INT
auth_sspi_client_init(SEC_CHAR* service,
                      WCHAR* principal,
                      ULONG flags,
                      WCHAR* user,
                      ULONG ulen,
                      WCHAR* domain,
                      ULONG dlen,
                      WCHAR* password,
                      ULONG plen,
                      sspi_client_state* state) {
    SECURITY_STATUS status;
    SEC_WINNT_AUTH_IDENTITY_W authIdentity;
    TimeStamp ignored;

    state->response = NULL;
    state->username = NULL;
    state->flags = flags;
    state->haveCred = 0;
    state->haveCtx = 0;
    state->spn = _strdup(service);
    if (state->spn == NULL) {
        PyErr_SetNone(PyExc_MemoryError);
        return AUTH_GSS_ERROR;
    }
    /* Convert RFC-2078 format to SPN */
    if (!strchr(state->spn, '/')) {
        SEC_CHAR* ptr = strchr(state->spn, '@');
        if (ptr) {
            *ptr = '/';
        }
    }

    if (user) {
        authIdentity.User = user;
        authIdentity.UserLength = ulen;
        authIdentity.Domain = domain;
        authIdentity.DomainLength = dlen;
        authIdentity.Password = password;
        authIdentity.PasswordLength = plen;
        authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    }

    status = AcquireCredentialsHandleW(/* Principal (NULL means current user) */
                                       principal,
                                       /* Security package name */
                                       L"kerberos",
                                       /* Credentials Use */
                                       SECPKG_CRED_OUTBOUND,
                                       /* LogonID (We don't use this) */
                                       NULL,
                                       /* AuthData */
                                       user ? &authIdentity : NULL,
                                       /* Always NULL */
                                       NULL,
                                       /* Always NULL */
                                       NULL,
                                       /* CredHandle */
                                       &state->cred,
                                       /* Expiry (Required but unused by us) */
                                       &ignored);
    if (status != SEC_E_OK) {
        set_krberror(status, "AcquireCredentialsHandle");
        return AUTH_GSS_ERROR;
    }
    state->haveCred = 1;
    return AUTH_GSS_COMPLETE;
}

INT
auth_sspi_client_step(sspi_client_state* state, SEC_CHAR* challenge) {
    SecBufferDesc inbuf;
    SecBuffer inBufs[1];
    SecBufferDesc outbuf;
    SecBuffer outBufs[1];
    ULONG ignored;
    SECURITY_STATUS status = AUTH_GSS_CONTINUE;
    DWORD len;

    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }

    inbuf.ulVersion = SECBUFFER_VERSION;
    inbuf.cBuffers = 1;
    inbuf.pBuffers = inBufs;
    inBufs[0].pvBuffer = NULL;
    inBufs[0].cbBuffer = 0;
    inBufs[0].BufferType = SECBUFFER_TOKEN;
    if (state->haveCtx) {
        inBufs[0].pvBuffer = base64_decode(challenge, &len);
        if (!inBufs[0].pvBuffer) {
            return AUTH_GSS_ERROR;
        }
        inBufs[0].cbBuffer = len;
    }

    outbuf.ulVersion = SECBUFFER_VERSION;
    outbuf.cBuffers = 1;
    outbuf.pBuffers = outBufs;
    outBufs[0].pvBuffer = NULL;
    outBufs[0].cbBuffer = 0;
    outBufs[0].BufferType = SECBUFFER_TOKEN;

    Py_BEGIN_ALLOW_THREADS
    status = InitializeSecurityContextA(/* CredHandle */
                                        &state->cred,
                                        /* CtxtHandle (NULL on first call) */
                                        state->haveCtx ? &state->ctx : NULL,
                                        /* Service Principal Name */
                                        state->spn,
                                        /* Flags */
                                        ISC_REQ_ALLOCATE_MEMORY | state->flags,
                                        /* Always 0 */
                                        0,
                                        /* Target data representation */
                                        SECURITY_NETWORK_DREP,
                                        /* Challenge (NULL on first call) */
                                        state->haveCtx ? &inbuf : NULL,
                                        /* Always 0 */
                                        0,
                                        /* CtxtHandle (Set on first call) */
                                        &state->ctx,
                                        /* Output */
                                        &outbuf,
                                        /* Context attributes */
                                        &ignored,
                                        /* Expiry (We don't use this) */
                                        NULL);
    Py_END_ALLOW_THREADS
    if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
        set_krberror(status, "InitializeSecurityContext");
        status = AUTH_GSS_ERROR;
        goto done;
    }
    state->haveCtx = 1;
    if (outBufs[0].cbBuffer) {
        state->response = base64_encode(outBufs[0].pvBuffer,
                                        outBufs[0].cbBuffer);
        if (!state->response) {
            status = AUTH_GSS_ERROR;
            goto done;
        }
    }
    if (status == SEC_E_OK) {
        /* Get authenticated username. */
        SecPkgContext_Names names;
        status = QueryContextAttributes(
            &state->ctx, SECPKG_ATTR_NAMES, &names);
        if (status != SEC_E_OK) {
            set_krberror(status, "QueryContextAttributes");
            status = AUTH_GSS_ERROR;
            goto done;
        }
        state->username = _strdup(names.sUserName);
        if (state->username == NULL) {
            PyErr_SetNone(PyExc_MemoryError);
            FreeContextBuffer(names.sUserName);
            status = AUTH_GSS_ERROR;
            goto done;
        }
        FreeContextBuffer(names.sUserName);
        status = AUTH_GSS_COMPLETE;
    } else {
        status = AUTH_GSS_CONTINUE;
    }
done:
    if (inBufs[0].pvBuffer) {
        free(inBufs[0].pvBuffer);
    }
    if (outBufs[0].pvBuffer) {
        FreeContextBuffer(outBufs[0].pvBuffer);
    }
    return status;
}

INT
auth_sspi_client_unwrap(sspi_client_state* state, SEC_CHAR* challenge) {
    SECURITY_STATUS status;
    DWORD len;
    SecBuffer wrapBufs[2];
    SecBufferDesc wrapBufDesc;
    wrapBufDesc.ulVersion = SECBUFFER_VERSION;
    wrapBufDesc.cBuffers = 2;
    wrapBufDesc.pBuffers = wrapBufs;

    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }

    if (!state->haveCtx) {
        set_uninitialized_context();
        return AUTH_GSS_ERROR;
    }

    wrapBufs[0].pvBuffer = base64_decode(challenge, &len);
    if (!wrapBufs[0].pvBuffer) {
        return AUTH_GSS_ERROR;
    }
    wrapBufs[0].cbBuffer = len;
    wrapBufs[0].BufferType = SECBUFFER_STREAM;

    wrapBufs[1].pvBuffer = NULL;
    wrapBufs[1].cbBuffer = 0;
    wrapBufs[1].BufferType = SECBUFFER_DATA;

    status = DecryptMessage(&state->ctx, &wrapBufDesc, 0, NULL);
    if (status == SEC_E_OK) {
        status = AUTH_GSS_COMPLETE;
    } else {
        set_krberror(status, "DecryptMessage");
        status = AUTH_GSS_ERROR;
        goto done;
    }
    if (wrapBufs[1].cbBuffer) {
        state->response = base64_encode(wrapBufs[1].pvBuffer,
                                        wrapBufs[1].cbBuffer);
        if (!state->response) {
            status = AUTH_GSS_ERROR;
        }
    }
done:
    if (wrapBufs[0].pvBuffer) {
        free(wrapBufs[0].pvBuffer);
    }
    return status;
}

INT
auth_sspi_client_wrap(sspi_client_state* state,
                      SEC_CHAR* data,
                      SEC_CHAR* user) {
    SECURITY_STATUS status;
    SecPkgContext_Sizes sizes;
    SecBuffer wrapBufs[3];
    SecBufferDesc wrapBufDesc;
    SEC_CHAR* decodedData = NULL;
    SEC_CHAR* inbuf;
    SIZE_T inbufSize;
    SEC_CHAR* outbuf;
    DWORD outbufSize;
    SEC_CHAR* plaintextMessage;
    DWORD plaintextMessageSize;

    if (state->response != NULL) {
        free(state->response);
        state->response = NULL;
    }

    if (!state->haveCtx) {
        set_uninitialized_context();
        return AUTH_GSS_ERROR;
    }

    status = QueryContextAttributes(&state->ctx, SECPKG_ATTR_SIZES, &sizes);
    if (status != SEC_E_OK) {
        set_krberror(status, "QueryContextAttributes");
        return AUTH_GSS_ERROR;
    }

    if (user) {
        /* Length of user + 4 bytes for security layer (see below). */
        plaintextMessageSize = (DWORD)strlen(user) + 4;
    } else {
        decodedData = base64_decode(data, &plaintextMessageSize);
        if (!decodedData) {
            return AUTH_GSS_ERROR;
        }
    }

    inbufSize =
        sizes.cbSecurityTrailer + plaintextMessageSize + sizes.cbBlockSize;
    inbuf = (SEC_CHAR*)malloc(inbufSize);
    if (inbuf == NULL) {
        free(decodedData);
        PyErr_SetNone(PyExc_MemoryError);
        return AUTH_GSS_ERROR;
    }

    plaintextMessage = inbuf + sizes.cbSecurityTrailer;
    if (user) {
        /* Authenticate the provided user. Unlike pykerberos, we don't
         * need any information from "data" to do that.
         * */
        plaintextMessage[0] = 1; /* No security layer */
        plaintextMessage[1] = 0;
        plaintextMessage[2] = 0;
        plaintextMessage[3] = 0;
        memcpy_s(
            plaintextMessage + 4,
            inbufSize - sizes.cbSecurityTrailer - 4,
            user,
            strlen(user));
    } else {
        /* No user provided. Just rewrap data. */
        memcpy_s(
            plaintextMessage,
            inbufSize - sizes.cbSecurityTrailer,
            decodedData,
            plaintextMessageSize);
        free(decodedData);
    }

    wrapBufDesc.cBuffers = 3;
    wrapBufDesc.pBuffers = wrapBufs;
    wrapBufDesc.ulVersion = SECBUFFER_VERSION;

    wrapBufs[0].cbBuffer = sizes.cbSecurityTrailer;
    wrapBufs[0].BufferType = SECBUFFER_TOKEN;
    wrapBufs[0].pvBuffer = inbuf;

    wrapBufs[1].cbBuffer = plaintextMessageSize;
    wrapBufs[1].BufferType = SECBUFFER_DATA;
    wrapBufs[1].pvBuffer = inbuf + sizes.cbSecurityTrailer;

    wrapBufs[2].cbBuffer = sizes.cbBlockSize;
    wrapBufs[2].BufferType = SECBUFFER_PADDING;
    wrapBufs[2].pvBuffer =
        inbuf + (sizes.cbSecurityTrailer + plaintextMessageSize);

    status = EncryptMessage(
        &state->ctx, SECQOP_WRAP_NO_ENCRYPT, &wrapBufDesc, 0);
    if (status != SEC_E_OK) {
        free(inbuf);
        set_krberror(status, "EncryptMessage");
        return AUTH_GSS_ERROR;
    }

    outbufSize =
        wrapBufs[0].cbBuffer + wrapBufs[1].cbBuffer + wrapBufs[2].cbBuffer;
    outbuf = (SEC_CHAR*)malloc(sizeof(SEC_CHAR) * outbufSize);
    if (outbuf == NULL) {
        free(inbuf);
        PyErr_SetNone(PyExc_MemoryError);
        return AUTH_GSS_ERROR;
    }
    memcpy_s(outbuf,
             outbufSize,
             wrapBufs[0].pvBuffer,
             wrapBufs[0].cbBuffer);
    memcpy_s(outbuf + wrapBufs[0].cbBuffer,
             outbufSize - wrapBufs[0].cbBuffer,
             wrapBufs[1].pvBuffer,
             wrapBufs[1].cbBuffer);
    memcpy_s(outbuf + wrapBufs[0].cbBuffer + wrapBufs[1].cbBuffer,
             outbufSize - wrapBufs[0].cbBuffer - wrapBufs[1].cbBuffer,
             wrapBufs[2].pvBuffer,
             wrapBufs[2].cbBuffer);
    state->response = base64_encode(outbuf, outbufSize);
    if (!state->response) {
        status = AUTH_GSS_ERROR;
    } else {
        status = AUTH_GSS_COMPLETE;
    }
    free(inbuf);
    free(outbuf);
    return status;
}

