/**
 * Network Security Support Provider Interface (NetSSPI)
 *
 * Copyright 2012-2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <fcntl.h>
#include <errno.h>

#ifndef _WIN32
#include <netdb.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#endif

#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/tchar.h>
#include <winpr/stream.h>

#include "../netsspi.h"

static PSecurityFunctionTableA TableA = NULL;
static PSecurityFunctionTableW TableW = NULL;

int netsspi_recv_query_security_package_info(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	UINT16 encoding;
	PSecPkgInfoA pPkgInfoA;
	PSecPkgInfoW pPkgInfoW;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_QUERY_SECURITY_PACKAGE_INFO_REQ req;
	NETSSPI_QUERY_SECURITY_PACKAGE_INFO_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));
	encoding = (hdr_req->Flags & NETSSPI_FLAGS_UNICODE) ? NETSSPI_STRING_UNICODE : NETSSPI_STRING_ANSI;

	netsspi_read_string(s, &req.PackageName);
	Stream_Free(s, TRUE);

	if (hdr_req->Flags & NETSSPI_FLAGS_UNICODE)
	{
		hdr_rsp.Status = TableW->QuerySecurityPackageInfoW((WCHAR*) req.PackageName.Buffer, &pPkgInfoW);
		pPkgInfoA = (PSecPkgInfoA) pPkgInfoW;
	}
	else
	{
		hdr_rsp.Status = TableA->QuerySecurityPackageInfoA((char*) req.PackageName.Buffer, &pPkgInfoA);
	}

	rsp.fCapabilities = pPkgInfoA->fCapabilities;
	rsp.wVersion = pPkgInfoA->wVersion;
	rsp.wRPCID = pPkgInfoA->wRPCID;
	rsp.cbMaxToken = pPkgInfoA->cbMaxToken;

	if (hdr_req->Flags & NETSSPI_FLAGS_UNICODE)
	{
		netsspi_init_string(&rsp.Name, (BYTE*) pPkgInfoW->Name, encoding);
		netsspi_init_string(&rsp.Comment, (BYTE*) pPkgInfoW->Comment, encoding);
	}
	else
	{
		netsspi_init_string(&rsp.Name, (BYTE*) pPkgInfoA->Name, encoding);
		netsspi_init_string(&rsp.Comment, (BYTE*) pPkgInfoA->Comment, encoding);
	}

	hdr_rsp.FunctionId = NETSSPI_QUERY_SECURITY_PACKAGE_INFO;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH + 16 +
			netsspi_string_length(&rsp.Name) + netsspi_string_length(&rsp.Comment);

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	Stream_Write_UINT32(s, rsp.fCapabilities);
	Stream_Write_UINT16(s, rsp.wVersion);
	Stream_Write_UINT16(s, rsp.wRPCID);
	Stream_Write_UINT32(s, rsp.cbMaxToken);
	netsspi_write_string(s, &rsp.Name);
	netsspi_write_string(s, &rsp.Comment);

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	netsspi_free_string(&req.PackageName);

	netsspi_free_string(&rsp.Name);
	netsspi_free_string(&rsp.Comment);

	return 0;
}

int netsspi_recv_accept_security_context(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	ULONG fContextAttr;
	PCredHandle phCredential;
	PCtxtHandle phContext;
	PCtxtHandle phNewContext;
	PSecBufferDesc pInput;
	PSecBufferDesc pOutput;
	PTimeStamp ptsTimeStamp;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_ACCEPT_SECURITY_CONTEXT_REQ req;
	NETSSPI_ACCEPT_SECURITY_CONTEXT_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	if (hdr_req->ExtFlags & NETSSPI_FIELD_01)
		netsspi_read_handle(s, &req.Credential);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_02)
		netsspi_read_handle(s, &req.Context);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_03)
	{
		int i;

		Stream_Read_UINT32(s, req.Input.ulVersion);
		Stream_Read_UINT32(s, req.Input.cBuffers);
		req.Input.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * req.Input.cBuffers);

		for (i = 0; i < (int) req.Input.cBuffers; i++)
		{
			Stream_Read_UINT32(s, req.Input.pBuffers[i].cbBuffer);
			Stream_Read_UINT32(s, req.Input.pBuffers[i].BufferType);
			req.Input.pBuffers[i].pvBuffer = malloc(req.Input.pBuffers[i].cbBuffer);
			Stream_Read(s, req.Input.pBuffers[i].pvBuffer, req.Input.pBuffers[i].cbBuffer);
		}
	}

	Stream_Read_UINT32(s, req.fContextReq);
	Stream_Read_UINT32(s, req.TargetDataRep);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_04)
		netsspi_read_handle(s, &req.NewContext);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_05)
	{
		int i;

		Stream_Read_UINT32(s, req.Output.ulVersion);
		Stream_Read_UINT32(s, req.Output.cBuffers);
		req.Output.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * req.Output.cBuffers);

		for (i = 0; i < (int) req.Output.cBuffers; i++)
		{
			Stream_Read_UINT32(s, req.Output.pBuffers[i].cbBuffer);
			Stream_Read_UINT32(s, req.Output.pBuffers[i].BufferType);
			req.Output.pBuffers[i].pvBuffer = NULL;
		}
	}

	Stream_Read_UINT32(s, req.fContextAttr);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_06)
		netsspi_read_timestamp(s, &req.TimeStamp);

	fContextAttr = 0;
	ptsTimeStamp = NULL;
	pInput = pOutput = NULL;
	phCredential = phContext = phNewContext = NULL;

	if (hdr_req->ExtFlags & NETSSPI_FIELD_01)
	{
		phCredential = (PCredHandle) malloc(sizeof(CredHandle));
		phCredential->dwLower = (ULONG_PTR) req.Credential.dwLower;
		phCredential->dwUpper = (ULONG_PTR) req.Credential.dwUpper;
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_02)
	{
		phContext = (PCtxtHandle) malloc(sizeof(CtxtHandle));
		phContext->dwLower = (ULONG_PTR) req.Context.dwLower;
		phContext->dwUpper = (ULONG_PTR) req.Context.dwUpper;
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_03)
	{
		int i;

		pInput = (PSecBufferDesc) malloc(sizeof(SecBufferDesc));
		pInput->ulVersion = req.Input.ulVersion;
		pInput->cBuffers = req.Input.cBuffers;
		pInput->pBuffers = (PSecBuffer) malloc(sizeof(SecBuffer) * pInput->cBuffers);

		for (i = 0; i < (int) pInput->cBuffers; i++)
		{
			pInput->pBuffers[i].cbBuffer = req.Input.pBuffers[i].cbBuffer;
			pInput->pBuffers[i].BufferType = req.Input.pBuffers[i].BufferType;
			pInput->pBuffers[i].pvBuffer = req.Input.pBuffers[i].pvBuffer;
		}
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_04)
	{
		phNewContext = (PCtxtHandle) malloc(sizeof(CtxtHandle));
		phNewContext->dwLower = (ULONG_PTR) req.NewContext.dwLower;
		phNewContext->dwUpper = (ULONG_PTR) req.NewContext.dwUpper;
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_05)
	{
		int i;

		pOutput = (PSecBufferDesc) malloc(sizeof(SecBufferDesc));
		pOutput->ulVersion = req.Output.ulVersion;
		pOutput->cBuffers = req.Output.cBuffers;
		pOutput->pBuffers = (PSecBuffer) malloc(sizeof(SecBuffer) * pOutput->cBuffers);

		for (i = 0; i < (int) pOutput->cBuffers; i++)
		{
			pOutput->pBuffers[i].cbBuffer = req.Output.pBuffers[i].cbBuffer;
			pOutput->pBuffers[i].BufferType = req.Output.pBuffers[i].BufferType;
			pOutput->pBuffers[i].pvBuffer = malloc(pOutput->pBuffers[i].cbBuffer);
		}
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_06)
	{
		ptsTimeStamp = (PTimeStamp) malloc(sizeof(TimeStamp));
		ptsTimeStamp->LowPart = req.TimeStamp.LowPart;
		ptsTimeStamp->HighPart = req.TimeStamp.HighPart;
	}

	hdr_rsp.Status = TableA->AcceptSecurityContext(phCredential, phContext, pInput, req.fContextReq,
			req.TargetDataRep, phNewContext, pOutput, &fContextAttr, ptsTimeStamp);

	printf("AcceptSecurityContext status: 0x%08X\n", hdr_rsp.Status);

	hdr_rsp.FunctionId = NETSSPI_ACCEPT_SECURITY_CONTEXT;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH + 4;

	if (phNewContext)
	{
		hdr_rsp.TotalLength += 16;
		hdr_rsp.ExtFlags |= NETSSPI_FIELD_01;
		rsp.NewContext.dwLower = phNewContext->dwLower;
		rsp.NewContext.dwUpper = phNewContext->dwUpper;
	}

	if (pOutput)
	{
		int i;
		hdr_rsp.TotalLength += 8;
		hdr_rsp.ExtFlags |= NETSSPI_FIELD_02;

		rsp.Output.ulVersion = pOutput->ulVersion;
		rsp.Output.cBuffers = pOutput->cBuffers;
		rsp.Output.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * rsp.Output.cBuffers);

		for (i = 0; i < (int) rsp.Output.cBuffers; i++)
		{
			rsp.Output.pBuffers[i].cbBuffer = pOutput->pBuffers[i].cbBuffer;
			rsp.Output.pBuffers[i].BufferType = pOutput->pBuffers[i].BufferType;
			rsp.Output.pBuffers[i].pvBuffer = malloc(pOutput->pBuffers[i].cbBuffer);
			CopyMemory(rsp.Output.pBuffers[i].pvBuffer, pOutput->pBuffers[i].pvBuffer, pOutput->pBuffers[i].cbBuffer);
			hdr_rsp.TotalLength += (8 + pOutput->pBuffers[i].cbBuffer);
		}
	}

	if (ptsTimeStamp)
	{
		hdr_rsp.TotalLength += 8;
		hdr_rsp.ExtFlags |= NETSSPI_FIELD_03;
		rsp.TimeStamp.LowPart = ptsTimeStamp->LowPart;
		rsp.TimeStamp.HighPart = ptsTimeStamp->HighPart;
	}

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_01)
		netsspi_write_handle(s, &rsp.NewContext);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_02)
	{
		int i;

		Stream_Write_UINT32(s, rsp.Output.ulVersion);
		Stream_Write_UINT32(s, rsp.Output.cBuffers);

		for (i = 0; i < (int) rsp.Output.cBuffers; i++)
		{
			Stream_Write_UINT32(s, rsp.Output.pBuffers[i].cbBuffer);
			Stream_Write_UINT32(s, rsp.Output.pBuffers[i].BufferType);
			Stream_Write(s, rsp.Output.pBuffers[i].pvBuffer, rsp.Output.pBuffers[i].cbBuffer);
		}
	}

	Stream_Write_UINT32(s, rsp.fContextAttr);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_03)
		netsspi_write_timestamp(s, &rsp.TimeStamp);

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_01)
		free(phCredential);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_02)
		free(phContext);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_03)
	{
		int i;

		for (i = 0; i < (int) req.Input.cBuffers; i++)
			free(req.Input.pBuffers[i].pvBuffer);

		free(req.Input.pBuffers);
		free(pInput->pBuffers);
		free(pInput);
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_04)
		free(phNewContext);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_05)
	{
		int i;

		for (i = 0; i < (int) pOutput->cBuffers; i++)
			free(pOutput->pBuffers[i].pvBuffer);

		free(pOutput->pBuffers);
		free(pOutput);
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_06)
		free(ptsTimeStamp);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_02)
	{
		int i;

		for (i = 0; i < (int) rsp.Output.cBuffers; i++)
			free(rsp.Output.pBuffers[i].pvBuffer);

		free(rsp.Output.pBuffers);
	}

	return 0;
}

int netsspi_recv_query_context_attributes(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	UINT16 encoding;
	CtxtHandle Context;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_QUERY_CONTEXT_ATTRIBUTES_REQ req;
	NETSSPI_QUERY_CONTEXT_ATTRIBUTES_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));
	encoding = (hdr_req->Flags & NETSSPI_FLAGS_UNICODE) ? NETSSPI_STRING_UNICODE : NETSSPI_STRING_ANSI;

	netsspi_read_handle(s, &(req.Context));
	Stream_Read_UINT32(s, req.ulAttribute);
	Stream_Free(s, TRUE);

	Context.dwLower = (ULONG_PTR) req.Context.dwLower;
	Context.dwUpper = (ULONG_PTR) req.Context.dwUpper;

	switch (req.ulAttribute)
	{
		case SECPKG_ATTR_SIZES:
			rsp.Length = sizeof(SecPkgContext_Sizes);
			break;

		default:
			break;
	}

	if (rsp.Length > 0)
		rsp.Buffer = malloc(rsp.Length);

	if (hdr_req->Flags & NETSSPI_FLAGS_UNICODE)
		hdr_rsp.Status = TableW->QueryContextAttributesW(&Context, req.ulAttribute, rsp.Buffer);
	else
		hdr_rsp.Status = TableA->QueryContextAttributesA(&Context, req.ulAttribute, rsp.Buffer);

	if (hdr_rsp.Status != SEC_E_OK)
		rsp.Length = 0;

	hdr_rsp.FunctionId = NETSSPI_QUERY_CONTEXT_ATTRIBUTES;
	hdr_rsp.Flags = (encoding == NETSSPI_STRING_UNICODE) ? NETSSPI_FLAGS_UNICODE : 0;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH + 4 + rsp.Length;

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	Stream_Write_UINT32(s, rsp.Length);
	Stream_Write(s, rsp.Buffer, rsp.Length);

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	if (rsp.Buffer)
		free(rsp.Buffer);

	return 0;
}

int netsspi_recv_impersonate_security_context(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	CtxtHandle Context;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_IMPERSONATE_SECURITY_CONTEXT_REQ req;
	NETSSPI_IMPERSONATE_SECURITY_CONTEXT_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	netsspi_read_handle(s, &(req.Context));

	Context.dwLower = (ULONG_PTR) req.Context.dwLower;
	Context.dwUpper = (ULONG_PTR) req.Context.dwUpper;

	hdr_rsp.Status = TableA->ImpersonateSecurityContext(&Context);

	printf("ImpersonateSecurityContext status: 0x%08X\n", hdr_rsp.Status);

	hdr_rsp.FunctionId = NETSSPI_IMPERSONATE_SECURITY_CONTEXT;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH;

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	return 0;
}

int netsspi_recv_revert_security_context(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	CtxtHandle Context;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_REVERT_SECURITY_CONTEXT_REQ req;
	NETSSPI_REVERT_SECURITY_CONTEXT_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	netsspi_read_handle(s, &(req.Context));

	Context.dwLower = (ULONG_PTR) req.Context.dwLower;
	Context.dwUpper = (ULONG_PTR) req.Context.dwUpper;

	hdr_rsp.Status = TableA->RevertSecurityContext(&Context);

	printf("RevertSecurityContext status: 0x%08X\n", hdr_rsp.Status);

	hdr_rsp.FunctionId = NETSSPI_REVERT_SECURITY_CONTEXT;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH;

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	return 0;
}

int netsspi_recv_acquire_credentials_handle(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	UINT16 encoding;
	TimeStamp Expiry;
	CredHandle Credential;
	PLUID pvLogonID = NULL;
	void* pAuthData = NULL;
	NETSSPI_HEADER_RSP hdr_rsp;
	SEC_WINNT_AUTH_IDENTITY identity;
	NETSSPI_ACQUIRE_CREDENTIALS_HANDLE_REQ req;
	NETSSPI_ACQUIRE_CREDENTIALS_HANDLE_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));
	encoding = (hdr_req->Flags & NETSSPI_FLAGS_UNICODE) ? NETSSPI_STRING_UNICODE : NETSSPI_STRING_ANSI;

	if (hdr_req->ExtFlags & NETSSPI_FIELD_01)
		netsspi_read_string(s, &req.Principal);

	netsspi_read_string(s, &req.Package);

	Stream_Read_UINT32(s, req.fCredentialUse);

	if (hdr_req->ExtFlags & NETSSPI_FIELD_02)
	{
		Stream_Read_UINT32(s, req.LogonID.LowPart);
		Stream_Read_UINT32(s, req.LogonID.HighPart);
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_03)
	{
		Stream_Read_UINT32(s, req.AuthDataLength);

		if (hdr_req->ExtFlags & NETSSPI_OPTION_01)
		{
			Stream_Read_UINT32(s, req.identity.Flags);

			netsspi_read_string(s, &req.identity.User);
			netsspi_read_string(s, &req.identity.Domain);
			netsspi_read_string(s, &req.identity.Password);
		}
		else
		{
			Stream_Seek(s, req.AuthDataLength);
		}
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_02)
	{
		pvLogonID = (PLUID) malloc(sizeof(LUID));
		pvLogonID->LowPart = req.LogonID.LowPart;
		pvLogonID->HighPart = req.LogonID.HighPart;
	}

	if (hdr_req->ExtFlags & NETSSPI_FIELD_03)
	{
		if (hdr_req->ExtFlags & NETSSPI_OPTION_01)
		{
			identity.Flags = req.identity.Flags;

			identity.UserLength = req.identity.User.Length;
			identity.DomainLength = req.identity.Domain.Length;
			identity.PasswordLength = req.identity.Password.Length;

			identity.User = (UINT16*) req.identity.User.Buffer;
			identity.Domain = (UINT16*) req.identity.Domain.Buffer;
			identity.Password = (UINT16*) req.identity.Password.Buffer;

			pAuthData = (void*) &identity;
		}
	}

	if (hdr_req->Flags & NETSSPI_FLAGS_UNICODE)
	{
		hdr_rsp.Status = TableW->AcquireCredentialsHandleW((WCHAR*) req.Principal.Buffer, (WCHAR*) req.Package.Buffer,
				req.fCredentialUse, pvLogonID, pAuthData, NULL, NULL, &Credential, &Expiry);
	}
	else
	{
		hdr_rsp.Status = TableA->AcquireCredentialsHandleA((char*) req.Principal.Buffer, (char*) req.Package.Buffer,
				req.fCredentialUse, pvLogonID, pAuthData, NULL, NULL, &Credential, &Expiry);
	}

	rsp.Credential.dwLower = Credential.dwLower;
	rsp.Credential.dwUpper = Credential.dwUpper;

	rsp.Expiry.LowPart = Expiry.LowPart;
	rsp.Expiry.HighPart = Expiry.HighPart;

	hdr_rsp.FunctionId = NETSSPI_ACQUIRE_CREDENTIALS_HANDLE;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH + 16 + 8;

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	netsspi_write_handle(s, &rsp.Credential);
	netsspi_write_timestamp(s, &rsp.Expiry);

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	netsspi_free_string(&req.Package);

	return 0;
}

int netsspi_recv_decrypt_message(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	int i;
	ULONG fQOP;
	CtxtHandle Context;
	PSecBufferDesc pMessage;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_DECRYPT_MESSAGE_REQ req;
	NETSSPI_DECRYPT_MESSAGE_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	netsspi_read_handle(s, &(req.Context));

	Stream_Read_UINT32(s, req.Message.ulVersion);
	Stream_Read_UINT32(s, req.Message.cBuffers);
	req.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * req.Message.cBuffers);

	for (i = 0; i < (int) req.Message.cBuffers; i++)
	{
		Stream_Read_UINT32(s, req.Message.pBuffers[i].cbBuffer);
		Stream_Read_UINT32(s, req.Message.pBuffers[i].BufferType);
		req.Message.pBuffers[i].pvBuffer = malloc(req.Message.pBuffers[i].cbBuffer);
		Stream_Read(s, req.Message.pBuffers[i].pvBuffer, req.Message.pBuffers[i].cbBuffer);
	}

	Stream_Read_UINT32(s, req.MessageSeqNo);

	Context.dwLower = (ULONG_PTR) req.Context.dwLower;
	Context.dwUpper = (ULONG_PTR) req.Context.dwUpper;

	pMessage = (PSecBufferDesc) malloc(sizeof(SecBufferDesc));
	pMessage->ulVersion = req.Message.ulVersion;
	pMessage->cBuffers = req.Message.cBuffers;
	pMessage->pBuffers = (PSecBuffer) malloc(sizeof(SecBuffer) * pMessage->cBuffers);

	for (i = 0; i < (int) pMessage->cBuffers; i++)
	{
		pMessage->pBuffers[i].cbBuffer = req.Message.pBuffers[i].cbBuffer;
		pMessage->pBuffers[i].BufferType = req.Message.pBuffers[i].BufferType;
		pMessage->pBuffers[i].pvBuffer = req.Message.pBuffers[i].pvBuffer;
	}

	hdr_rsp.Status = TableA->DecryptMessage(&Context, pMessage, req.MessageSeqNo, &fQOP);

	printf("DecryptMessage status: 0x%08X\n", hdr_rsp.Status);

	hdr_rsp.FunctionId = NETSSPI_DECRYPT_MESSAGE;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH + 4;

	hdr_rsp.TotalLength += 8;

	rsp.Message.ulVersion = pMessage->ulVersion;
	rsp.Message.cBuffers = pMessage->cBuffers;
	rsp.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * pMessage->cBuffers);

	for (i = 0; i < (int) pMessage->cBuffers; i++)
	{
		rsp.Message.pBuffers[i].cbBuffer = pMessage->pBuffers[i].cbBuffer;
		rsp.Message.pBuffers[i].BufferType = pMessage->pBuffers[i].BufferType;
		rsp.Message.pBuffers[i].pvBuffer = malloc(pMessage->pBuffers[i].cbBuffer);
		CopyMemory(rsp.Message.pBuffers[i].pvBuffer, pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
		hdr_rsp.TotalLength += (8 + rsp.Message.pBuffers[i].cbBuffer);
	}

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	Stream_Write_UINT32(s, rsp.Message.ulVersion);
	Stream_Write_UINT32(s, rsp.Message.cBuffers);

	for (i = 0; i < (int) rsp.Message.cBuffers; i++)
	{
		Stream_Write_UINT32(s, rsp.Message.pBuffers[i].cbBuffer);
		Stream_Write_UINT32(s, rsp.Message.pBuffers[i].BufferType);
		Stream_Write(s, rsp.Message.pBuffers[i].pvBuffer, rsp.Message.pBuffers[i].cbBuffer);
	}

	Stream_Write_UINT32(s, rsp.fQOP);

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	return 0;
}

int netsspi_recv_encrypt_message(NETSSPI_CONTEXT* context, wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	int i;
	CtxtHandle Context;
	PSecBufferDesc pMessage;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_ENCRYPT_MESSAGE_REQ req;
	NETSSPI_ENCRYPT_MESSAGE_RSP rsp;

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	netsspi_read_handle(s, &(req.Context));

	Stream_Read_UINT32(s, req.fQOP);

	Stream_Read_UINT32(s, req.Message.ulVersion);
	Stream_Read_UINT32(s, req.Message.cBuffers);
	req.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * req.Message.cBuffers);

	for (i = 0; i < (int) req.Message.cBuffers; i++)
	{
		Stream_Read_UINT32(s, req.Message.pBuffers[i].cbBuffer);
		Stream_Read_UINT32(s, req.Message.pBuffers[i].BufferType);
		req.Message.pBuffers[i].pvBuffer = malloc(req.Message.pBuffers[i].cbBuffer);
		Stream_Read(s, req.Message.pBuffers[i].pvBuffer, req.Message.pBuffers[i].cbBuffer);
	}

	Stream_Read_UINT32(s, req.MessageSeqNo);

	Context.dwLower = (ULONG_PTR) req.Context.dwLower;
	Context.dwUpper = (ULONG_PTR) req.Context.dwUpper;

	pMessage = (PSecBufferDesc) malloc(sizeof(SecBufferDesc));
	pMessage->ulVersion = req.Message.ulVersion;
	pMessage->cBuffers = req.Message.cBuffers;
	pMessage->pBuffers = (PSecBuffer) malloc(sizeof(SecBuffer) * pMessage->cBuffers);

	for (i = 0; i < (int) pMessage->cBuffers; i++)
	{
		pMessage->pBuffers[i].cbBuffer = req.Message.pBuffers[i].cbBuffer;
		pMessage->pBuffers[i].BufferType = req.Message.pBuffers[i].BufferType;
		pMessage->pBuffers[i].pvBuffer = req.Message.pBuffers[i].pvBuffer;
	}

	hdr_rsp.Status = TableA->EncryptMessage(&Context, req.fQOP, pMessage, req.MessageSeqNo);

	printf("EncryptMessage status: 0x%08X\n", hdr_rsp.Status);

	hdr_rsp.FunctionId = NETSSPI_ENCRYPT_MESSAGE;
	hdr_rsp.TotalLength = NETSSPI_HEADER_RSP_LENGTH;

	hdr_rsp.TotalLength += 8;

	rsp.Message.ulVersion = pMessage->ulVersion;
	rsp.Message.cBuffers = pMessage->cBuffers;
	rsp.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * pMessage->cBuffers);

	for (i = 0; i < (int) pMessage->cBuffers; i++)
	{
		rsp.Message.pBuffers[i].cbBuffer = pMessage->pBuffers[i].cbBuffer;
		rsp.Message.pBuffers[i].BufferType = pMessage->pBuffers[i].BufferType;
		rsp.Message.pBuffers[i].pvBuffer = malloc(pMessage->pBuffers[i].cbBuffer);
		CopyMemory(rsp.Message.pBuffers[i].pvBuffer, pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
		hdr_rsp.TotalLength += (8 + rsp.Message.pBuffers[i].cbBuffer);
	}

	s = Stream_New(NULL, hdr_rsp.TotalLength);

	netsspi_write_header_rsp(s, &hdr_rsp);

	Stream_Write_UINT32(s, rsp.Message.ulVersion);
	Stream_Write_UINT32(s, rsp.Message.cBuffers);

	for (i = 0; i < (int) rsp.Message.cBuffers; i++)
	{
		Stream_Write_UINT32(s, rsp.Message.pBuffers[i].cbBuffer);
		Stream_Write_UINT32(s, rsp.Message.pBuffers[i].BufferType);
		Stream_Write(s, rsp.Message.pBuffers[i].pvBuffer, rsp.Message.pBuffers[i].cbBuffer);
	}

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	return 0;
}

int netsspi_recv(NETSSPI_CONTEXT* context, wStream* s)
{
	NETSSPI_HEADER_REQ hdr_req;

	netsspi_read_header_req(s, &hdr_req);

	switch (hdr_req.FunctionId)
	{
		case NETSSPI_ENUMERATE_SECURITY_PACKAGES:
			break;

		case NETSSPI_QUERY_CREDENTIALS_ATTRIBUTES:
			break;

		case NETSSPI_ACQUIRE_CREDENTIALS_HANDLE:
			netsspi_recv_acquire_credentials_handle(context, s, &hdr_req);
			break;

		case NETSSPI_FREE_CREDENTIALS_HANDLE:
			break;

		case NETSSPI_INITIALIZE_SECURITY_CONTEXT:
			break;

		case NETSSPI_ACCEPT_SECURITY_CONTEXT:
			netsspi_recv_accept_security_context(context, s, &hdr_req);
			break;

		case NETSSPI_COMPLETE_AUTH_TOKEN:
			break;

		case NETSSPI_DELETE_SECURITY_CONTEXT:
			break;

		case NETSSPI_APPLY_CONTROL_TOKEN:
			break;

		case NETSSPI_QUERY_CONTEXT_ATTRIBUTES:
			netsspi_recv_query_context_attributes(context, s, &hdr_req);
			break;

		case NETSSPI_IMPERSONATE_SECURITY_CONTEXT:
			netsspi_recv_impersonate_security_context(context, s, &hdr_req);
			break;

		case NETSSPI_REVERT_SECURITY_CONTEXT:
			netsspi_recv_revert_security_context(context, s, &hdr_req);
			break;

		case NETSSPI_MAKE_SIGNATURE:
			break;

		case NETSSPI_VERIFY_SIGNATURE:
			break;

		case NETSSPI_FREE_CONTEXT_BUFFER:
			break;

		case NETSSPI_QUERY_SECURITY_PACKAGE_INFO:
			netsspi_recv_query_security_package_info(context, s, &hdr_req);
			break;

		case NETSSPI_EXPORT_SECURITY_CONTEXT:
			break;

		case NETSSPI_IMPORT_SECURITY_CONTEXT:
			break;

		case NETSSPI_ADD_CREDENTIALS:
			break;

		case NETSSPI_QUERY_SECURITY_CONTEXT_TOKEN:
			break;

		case NETSSPI_ENCRYPT_MESSAGE:
			netsspi_recv_encrypt_message(context, s, &hdr_req);
			break;

		case NETSSPI_DECRYPT_MESSAGE:
			netsspi_recv_decrypt_message(context, s, &hdr_req);
			break;

		case NETSSPI_SET_CONTEXT_ATTRIBUTES:
			break;
	}

	return 0;
}

int netsspi_accept_client(NETSSPI_CONTEXT* context)
{
	wStream* s;

	sspi_GlobalInit();

#ifndef _WIN32
	TableA = InitSecurityInterfaceA();
	TableW = InitSecurityInterfaceW();
#else
	{
		HMODULE hSSPI;
		INIT_SECURITY_INTERFACE_W pInitSecurityInterfaceW;
		INIT_SECURITY_INTERFACE_A pInitSecurityInterfaceA;

		hSSPI = LoadLibrary(_T("secur32.dll"));
		pInitSecurityInterfaceW = (INIT_SECURITY_INTERFACE_W) GetProcAddress(hSSPI, "InitSecurityInterfaceW");
		pInitSecurityInterfaceA = (INIT_SECURITY_INTERFACE_A) GetProcAddress(hSSPI, "InitSecurityInterfaceA");

		TableA = pInitSecurityInterfaceA();
		TableW = pInitSecurityInterfaceW();
	}
#endif

	while (1)
	{
		s = netsspi_recv_message(context);

		if (!s)
			break;

		netsspi_recv(context, s);
	}

	return 0;
}

#ifdef _WIN32
BOOL winsock_init()
{
	WSADATA wsaData;

	if (WSAStartup(0x101, &wsaData) != 0)
		return FALSE;

	return TRUE;
}
#endif

int main(int argc, char* argv[])
{
	int client_sockfd;
	socklen_t addr_size;
	NETSSPI_CONTEXT* context;

#ifdef _WIN32
	winsock_init();
#endif

	context = netsspi_new(TRUE);

	if (_tcscmp(_T("TcpSocket"), context->Transport) == 0)
	{
		struct sockaddr_storage client_sockaddr;

		netsspi_tcp_socket_open(context);

		while (1)
		{
			addr_size = sizeof(client_sockaddr);
			client_sockfd = accept(context->sockfd, (struct sockaddr*) &client_sockaddr, &addr_size);

			if (client_sockfd == -1)
			{
#ifdef _WIN32
				int wsa_error = WSAGetLastError();

				/* No data available */
				if (wsa_error == WSAEWOULDBLOCK)
					continue;
#else
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
#endif

				perror("accept");
				continue;
			}

			printf("accepted client\n");

			netsspi_tcp_socket_init(context);
			context->sockfd = client_sockfd;

			netsspi_accept_client(context);
		}
	}
#ifndef _WIN32
	else if (_tcscmp(_T("IpcSocket"), context->Transport) == 0)
	{
		int sockfd;
		struct sockaddr client_sockaddr;

		sockfd = netsspi_ipc_socket_open(context);

		while (1)
		{
			addr_size = sizeof(client_sockaddr);
			client_sockfd = accept(sockfd, (struct sockaddr*) &client_sockaddr, &addr_size);

			if (client_sockfd == -1)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;

				perror("accept");
				continue;
			}

			printf("accepted client\n");

			context->sockfd = client_sockfd;
			netsspi_ipc_socket_init(context);

			netsspi_accept_client(context);
		}
	}
#else
	else if (_tcscmp(_T("SerialDevice"), context->Transport) == 0)
	{
		netsspi_serial_device_open(context);
		netsspi_serial_device_init(context);
		netsspi_accept_client(context);
	}
#endif
	else
	{
		_tprintf(_T("Unsupported NetSSPI transport type: %s\n"), context->Transport);
	}

	return 0;
}
