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

#define SECURITY_WIN32 1 /* Required for SSPI */

#include <Python.h>
#include <Windows.h>
#include <sspi.h>

#define AUTH_GSS_ERROR -1
#define AUTH_GSS_COMPLETE 1
#define AUTH_GSS_CONTINUE 0

typedef struct {
    CredHandle cred;
    CtxtHandle ctx;
    SEC_CHAR* spn;
    SEC_CHAR* response;
    SEC_CHAR* username;
    ULONG flags;
    UCHAR haveCred;
    UCHAR haveCtx;
} sspi_client_state;

VOID destroy_sspi_client_state(sspi_client_state* state);
INT auth_sspi_client_init(SEC_CHAR* service,
                          SEC_CHAR* principal,
                          ULONG flags,
                          SEC_CHAR* user,
                          SEC_CHAR* domain,
                          SEC_CHAR* password,
                          sspi_client_state* state);
INT auth_sspi_client_step(sspi_client_state* state, SEC_CHAR* challenge);
INT auth_sspi_client_unwrap(sspi_client_state* state, SEC_CHAR* challenge);
INT auth_sspi_client_wrap(sspi_client_state* state,
                          SEC_CHAR* data,
                          SEC_CHAR* user);
