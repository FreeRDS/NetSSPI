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

#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/print.h>
#include <winpr/tchar.h>
#include <winpr/stream.h>

#include "../netsspi.h"

static NETSSPI_CONTEXT* context = NULL;

SecurityFunctionTableA NETSSPI_SecurityFunctionTableA;
SecurityFunctionTableW NETSSPI_SecurityFunctionTableW;

/* Package Management */

void netsspi_init()
{
	if (context)
	{
		_tprintf(_T("Reusing existing NetSSPI context (Transport: %s, Target: %s)\n"),
			context->Transport, context->Target);
		return;
	}

	context = netsspi_new(FALSE);

	if (_tcscmp(_T("TcpSocket"), context->Transport) == 0)
	{
		netsspi_tcp_socket_open(context);
		netsspi_tcp_socket_init(context);
	}
#ifndef _WIN32
	else if (_tcscmp(_T("IpcSocket"), context->Transport) == 0)
	{
		netsspi_ipc_socket_connect(context);
		netsspi_ipc_socket_init(context);
	}
#else
	else if (_tcscmp(_T("SerialDevice"), context->Transport) == 0)
	{
		netsspi_serial_device_open(context);
		netsspi_serial_device_init(context);
	}
#endif
	else
	{
		_tprintf(_T("Unsupported NetSSPI transport type: %s\n"), context->Transport);
	}
}

PSecurityFunctionTableW SEC_ENTRY InitSecurityInterfaceW(void)
{
	netsspi_init();

	return &NETSSPI_SecurityFunctionTableW;
}

PSecurityFunctionTableA SEC_ENTRY InitSecurityInterfaceA(void)
{
	netsspi_init();

	return &NETSSPI_SecurityFunctionTableA;
}

SECURITY_STATUS SEC_ENTRY netsspi_EnumerateSecurityPackagesW(ULONG* pcPackages, PSecPkgInfoW* ppPackageInfo)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_EnumerateSecurityPackagesA(ULONG* pcPackages, PSecPkgInfoA* ppPackageInfo)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_QuerySecurityPackageInfoX(BYTE* pszPackageName, PSecPkgInfoA* ppPackageInfo, UINT16 encoding)
{
	wStream* s;
	SecPkgInfoA* pPackageInfoA;
	SecPkgInfoW* pPackageInfoW;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_QUERY_SECURITY_PACKAGE_INFO_REQ req;
	NETSSPI_QUERY_SECURITY_PACKAGE_INFO_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	netsspi_init_string(&req.PackageName, pszPackageName, encoding);

	hdr_req.FunctionId = NETSSPI_QUERY_SECURITY_PACKAGE_INFO;
	hdr_req.Flags = (encoding == NETSSPI_STRING_UNICODE) ? NETSSPI_FLAGS_UNICODE : 0;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 2 + netsspi_string_length(&req.PackageName);

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	netsspi_write_string(s, &req.PackageName);

	/* Step 3: Send */

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	Stream_Read_UINT32(s, rsp.fCapabilities);
	Stream_Read_UINT16(s, rsp.wVersion);
	Stream_Read_UINT16(s, rsp.wRPCID);
	Stream_Read_UINT32(s, rsp.cbMaxToken);

	netsspi_read_string(s, &rsp.Name);
	netsspi_read_string(s, &rsp.Comment);

	if (encoding == NETSSPI_STRING_UNICODE)
	{
		pPackageInfoW = (SecPkgInfoW*) malloc(sizeof(SecPkgInfoW));
		pPackageInfoA = (SecPkgInfoA*) pPackageInfoW;
	}
	else
	{
		pPackageInfoA = (SecPkgInfoA*) malloc(sizeof(SecPkgInfoA));
	}

	pPackageInfoA->fCapabilities = rsp.fCapabilities;
	pPackageInfoA->wVersion = rsp.wVersion;
	pPackageInfoA->wRPCID = rsp.wRPCID;
	pPackageInfoA->cbMaxToken = rsp.cbMaxToken;

	if (encoding == NETSSPI_STRING_UNICODE)
	{
		pPackageInfoW->Name = _wcsdup((WCHAR*) rsp.Name.Buffer);
		pPackageInfoW->Comment = _wcsdup((WCHAR*) rsp.Comment.Buffer);
	}
	else
	{
		pPackageInfoA->Name = _strdup((char*) rsp.Name.Buffer);
		pPackageInfoA->Comment = _strdup((char*) rsp.Comment.Buffer);
	}

	*(ppPackageInfo) = pPackageInfoA;

	/* Step 6: Deallocate */

	netsspi_free_string(&req.PackageName);

	netsspi_free_string(&rsp.Name);
	netsspi_free_string(&rsp.Comment);

	return hdr_rsp.Status;
}

SECURITY_STATUS SEC_ENTRY netsspi_QuerySecurityPackageInfoW(SEC_WCHAR* pszPackageName, PSecPkgInfoW* ppPackageInfo)
{
	return netsspi_QuerySecurityPackageInfoX((BYTE*) pszPackageName, (PSecPkgInfoA*) ppPackageInfo, NETSSPI_STRING_UNICODE);
}

SECURITY_STATUS SEC_ENTRY netsspi_QuerySecurityPackageInfoA(SEC_CHAR* pszPackageName, PSecPkgInfoA* ppPackageInfo)
{
	return netsspi_QuerySecurityPackageInfoX((BYTE*) pszPackageName, (PSecPkgInfoA*) ppPackageInfo, NETSSPI_STRING_ANSI);
}

/* Credential Management */

SECURITY_STATUS SEC_ENTRY netsspi_AcquireCredentialsHandleX(BYTE* pszPrincipal, BYTE* pszPackage,
		ULONG fCredentialUse, void* pvLogonID, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn,
		void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry, UINT16 encoding)
{
	wStream* s;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	SEC_WINNT_AUTH_IDENTITY* identity = NULL;
	NETSSPI_ACQUIRE_CREDENTIALS_HANDLE_REQ req;
	NETSSPI_ACQUIRE_CREDENTIALS_HANDLE_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	hdr_req.FunctionId = NETSSPI_ACQUIRE_CREDENTIALS_HANDLE;
	hdr_req.Flags = (encoding == NETSSPI_STRING_UNICODE) ? NETSSPI_FLAGS_UNICODE : 0;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 4;

	if (pszPrincipal)
	{
		hdr_req.ExtFlags |= NETSSPI_FIELD_01;
		netsspi_init_string(&req.Principal, pszPrincipal, encoding);
		hdr_req.TotalLength += 2 + netsspi_string_length(&req.Principal);
	}

	netsspi_init_string(&req.Package, pszPackage, encoding);
	hdr_req.TotalLength += 2 + netsspi_string_length(&req.Package);

	req.fCredentialUse = fCredentialUse;

	if (pvLogonID)
	{
		hdr_req.ExtFlags |= NETSSPI_FIELD_02;
		req.LogonID.LowPart = ((PLUID) pvLogonID)->LowPart;
		req.LogonID.HighPart = ((PLUID) pvLogonID)->HighPart;
		hdr_req.TotalLength += 8;
	}

	if (pAuthData)
	{
		hdr_req.ExtFlags |= NETSSPI_FIELD_03;
		hdr_req.ExtFlags |= NETSSPI_OPTION_01;
		identity = (SEC_WINNT_AUTH_IDENTITY*) pAuthData;

		req.identity.Flags = identity->Flags;

		if (req.identity.Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
		{
			netsspi_init_string_ex(&(req.identity.User), (BYTE*) identity->User, (UINT16) identity->UserLength, NETSSPI_STRING_UNICODE);
			netsspi_init_string_ex(&(req.identity.Domain), (BYTE*) identity->Domain, (UINT16) identity->DomainLength, NETSSPI_STRING_UNICODE);
			netsspi_init_string_ex(&(req.identity.Password), (BYTE*) identity->Password, (UINT16) identity->PasswordLength, NETSSPI_STRING_UNICODE);
		}
		else
		{
			netsspi_init_string_ex(&(req.identity.User), (BYTE*) identity->User, (UINT16) identity->UserLength, NETSSPI_STRING_ANSI);
			netsspi_init_string_ex(&(req.identity.Domain), (BYTE*) identity->Domain, (UINT16) identity->DomainLength, NETSSPI_STRING_ANSI);
			netsspi_init_string_ex(&(req.identity.Password), (BYTE*) identity->Password, (UINT16) identity->PasswordLength, NETSSPI_STRING_ANSI);
		}

		req.AuthDataLength = 10 + netsspi_string_length(&req.identity.User) +
				netsspi_string_length(&req.identity.Domain) + netsspi_string_length(&req.identity.Password);

		hdr_req.TotalLength += 4 + req.AuthDataLength;
	}

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_01)
		netsspi_write_string(s, &req.Principal);

	netsspi_write_string(s, &req.Package);

	Stream_Write_UINT32(s, req.fCredentialUse);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_02)
	{
		Stream_Write_UINT32(s, req.LogonID.LowPart);
		Stream_Write_UINT32(s, req.LogonID.HighPart);
	}

	if (hdr_req.ExtFlags & NETSSPI_FIELD_03)
	{
		Stream_Write_UINT32(s, req.AuthDataLength);

		if (hdr_req.ExtFlags & NETSSPI_OPTION_01)
		{
			Stream_Write_UINT32(s, req.identity.Flags);
			netsspi_write_string(s, &req.identity.User);
			netsspi_write_string(s, &req.identity.Domain);
			netsspi_write_string(s, &req.identity.Password);
		}
	}

	/* Step 3: Send */

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	netsspi_read_handle(s, &(rsp.Credential));
	netsspi_read_timestamp(s, &(rsp.Expiry));

	if (phCredential)
	{
		phCredential->dwLower = (ULONG_PTR) rsp.Credential.dwLower;
		phCredential->dwUpper = (ULONG_PTR) rsp.Credential.dwUpper;
	}

	if (ptsExpiry)
	{
		ptsExpiry->LowPart = rsp.Expiry.LowPart;
		ptsExpiry->HighPart = rsp.Expiry.HighPart;
	}

	/* Step 6: Deallocate */

	return hdr_rsp.Status;
}

SECURITY_STATUS SEC_ENTRY netsspi_AcquireCredentialsHandleW(SEC_WCHAR* pszPrincipal, SEC_WCHAR* pszPackage,
		ULONG fCredentialUse, void* pvLogonID, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn,
		void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
	return netsspi_AcquireCredentialsHandleX((BYTE*) pszPrincipal, (BYTE*) pszPackage, fCredentialUse, pvLogonID,
			pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry, NETSSPI_STRING_UNICODE);
}

SECURITY_STATUS SEC_ENTRY netsspi_AcquireCredentialsHandleA(SEC_CHAR* pszPrincipal, SEC_CHAR* pszPackage,
		ULONG fCredentialUse, void* pvLogonID, void* pAuthData, SEC_GET_KEY_FN pGetKeyFn,
		void* pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
	return netsspi_AcquireCredentialsHandleX((BYTE*) pszPrincipal, (BYTE*) pszPackage, fCredentialUse, pvLogonID,
			pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry, NETSSPI_STRING_ANSI);
}

SECURITY_STATUS SEC_ENTRY netsspi_ExportSecurityContext(PCtxtHandle phContext, ULONG fFlags, PSecBuffer pPackedContext, HANDLE* pToken)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_FreeCredentialsHandle(PCredHandle phCredential)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_ImportSecurityContextW(SEC_WCHAR* pszPackage, PSecBuffer pPackedContext, void* pToken, PCtxtHandle phContext)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_ImportSecurityContextA(SEC_CHAR* pszPackage, PSecBuffer pPackedContext, void* pToken, PCtxtHandle phContext)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_QueryCredentialsAttributesW(PCredHandle phCredential, ULONG ulAttribute, void* pBuffer)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_QueryCredentialsAttributesA(PCredHandle phCredential, ULONG ulAttribute, void* pBuffer)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

/* Context Management */

SECURITY_STATUS SEC_ENTRY netsspi_AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext,
		PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext,
		PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsTimeStamp)
{
	wStream* s;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_ACCEPT_SECURITY_CONTEXT_REQ req;
	NETSSPI_ACCEPT_SECURITY_CONTEXT_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	hdr_req.FunctionId = NETSSPI_ACCEPT_SECURITY_CONTEXT;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 12;

	if (phCredential)
	{
		hdr_req.TotalLength += 16;
		hdr_req.ExtFlags |= NETSSPI_FIELD_01;
		req.Credential.dwLower = phCredential->dwLower;
		req.Credential.dwUpper = phCredential->dwUpper;
	}

	if (phContext)
	{
		hdr_req.TotalLength += 16;
		hdr_req.ExtFlags |= NETSSPI_FIELD_02;
		req.Context.dwLower = phContext->dwLower;
		req.Context.dwUpper = phContext->dwUpper;
	}

	if (pInput)
	{
		int i;

		hdr_req.TotalLength += 8;
		hdr_req.ExtFlags |= NETSSPI_FIELD_03;

		req.Input.ulVersion = pInput->ulVersion;
		req.Input.cBuffers = pInput->cBuffers;
		req.Input.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * pInput->cBuffers);

		for (i = 0; i < (int) pInput->cBuffers; i++)
		{
			req.Input.pBuffers[i].cbBuffer = pInput->pBuffers[i].cbBuffer;
			req.Input.pBuffers[i].BufferType = pInput->pBuffers[i].BufferType;
			req.Input.pBuffers[i].pvBuffer = malloc(pInput->pBuffers[i].cbBuffer);
			CopyMemory(req.Input.pBuffers[i].pvBuffer, pInput->pBuffers[i].pvBuffer, pInput->pBuffers[i].cbBuffer);
			hdr_req.TotalLength += (8 + req.Input.pBuffers[i].cbBuffer);
		}
	}

	req.fContextReq = fContextReq;
	req.TargetDataRep = TargetDataRep;

	if (phNewContext)
	{
		hdr_req.TotalLength += 16;
		hdr_req.ExtFlags |= NETSSPI_FIELD_04;
		req.NewContext.dwLower = phNewContext->dwLower;
		req.NewContext.dwUpper = phNewContext->dwUpper;
	}

	if (pOutput)
	{
		int i;

		hdr_req.TotalLength += 8;
		hdr_req.ExtFlags |= NETSSPI_FIELD_05;

		req.Output.ulVersion = pOutput->ulVersion;
		req.Output.cBuffers = pOutput->cBuffers;
		req.Output.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * pOutput->cBuffers);

		for (i = 0; i < (int) pOutput->cBuffers; i++)
		{
			req.Output.pBuffers[i].cbBuffer = pOutput->pBuffers[i].cbBuffer;
			req.Output.pBuffers[i].BufferType = pOutput->pBuffers[i].BufferType;
			req.Output.pBuffers[i].pvBuffer = NULL;
			hdr_req.TotalLength += 8;
		}
	}

	if (ptsTimeStamp)
	{
		hdr_req.TotalLength += 8;
		hdr_req.ExtFlags |= NETSSPI_FIELD_06;
		req.TimeStamp.LowPart = ptsTimeStamp->LowPart;
		req.TimeStamp.HighPart = ptsTimeStamp->HighPart;
	}

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_01)
		netsspi_write_handle(s, &req.Credential);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_02)
		netsspi_write_handle(s, &req.Context);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_03)
	{
		int i;

		Stream_Write_UINT32(s, req.Input.ulVersion);
		Stream_Write_UINT32(s, req.Input.cBuffers);

		for (i = 0; i < (int) req.Input.cBuffers; i++)
		{
			Stream_Write_UINT32(s, req.Input.pBuffers[i].cbBuffer);
			Stream_Write_UINT32(s, req.Input.pBuffers[i].BufferType);
			Stream_Write(s, req.Input.pBuffers[i].pvBuffer, req.Input.pBuffers[i].cbBuffer);
		}
	}

	Stream_Write_UINT32(s, req.fContextReq);
	Stream_Write_UINT32(s, req.TargetDataRep);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_04)
		netsspi_write_handle(s, &req.NewContext);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_05)
	{
		int i;

		Stream_Write_UINT32(s, req.Output.ulVersion);
		Stream_Write_UINT32(s, req.Output.cBuffers);

		for (i = 0; i < (int) req.Output.cBuffers; i++)
		{
			Stream_Write_UINT32(s, req.Output.pBuffers[i].cbBuffer);
			Stream_Write_UINT32(s, req.Output.pBuffers[i].BufferType);
		}
	}

	Stream_Write_UINT32(s, req.fContextAttr);

	if (hdr_req.ExtFlags & NETSSPI_FIELD_06)
		netsspi_write_timestamp(s, &req.TimeStamp);

	/* Step 3: Send */

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_01)
		netsspi_read_handle(s, &rsp.NewContext);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_02)
	{
		int i;

		Stream_Read_UINT32(s, rsp.Output.ulVersion);
		Stream_Read_UINT32(s, rsp.Output.cBuffers);
		rsp.Output.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * rsp.Output.cBuffers);

		for (i = 0; i < (int) rsp.Output.cBuffers; i++)
		{
			Stream_Read_UINT32(s, rsp.Output.pBuffers[i].cbBuffer);
			Stream_Read_UINT32(s, rsp.Output.pBuffers[i].BufferType);
			rsp.Output.pBuffers[i].pvBuffer = malloc(rsp.Output.pBuffers[i].cbBuffer);
			Stream_Read(s, rsp.Output.pBuffers[i].pvBuffer, rsp.Output.pBuffers[i].cbBuffer);
		}
	}

	Stream_Read_UINT32(s, rsp.fContextAttr);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_03)
		netsspi_read_timestamp(s, &rsp.TimeStamp);

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_01)
	{
		if (phNewContext)
		{
			phNewContext->dwLower = (ULONG_PTR) rsp.NewContext.dwLower;
			phNewContext->dwUpper = (ULONG_PTR) rsp.NewContext.dwUpper;
		}
	}

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_02)
	{
		int i;

		for (i = 0; i < (int) rsp.Output.cBuffers; i++)
		{
			pOutput->pBuffers[i].cbBuffer = rsp.Output.pBuffers[i].cbBuffer;
			CopyMemory(pOutput->pBuffers[i].pvBuffer, rsp.Output.pBuffers[i].pvBuffer, pOutput->pBuffers[i].cbBuffer);
		}
	}

	*pfContextAttr = rsp.fContextAttr;

	if (hdr_rsp.ExtFlags & NETSSPI_FIELD_03)
	{
		if (ptsTimeStamp)
		{
			ptsTimeStamp->LowPart = rsp.TimeStamp.LowPart;
			ptsTimeStamp->HighPart = rsp.TimeStamp.HighPart;
		}
	}

	/* Step 6: Deallocate */

	return hdr_rsp.Status;
}

SECURITY_STATUS SEC_ENTRY netsspi_ApplyControlToken(PCtxtHandle phContext, PSecBufferDesc pInput)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_CompleteAuthToken(PCtxtHandle phContext, PSecBufferDesc pToken)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_DeleteSecurityContext(PCtxtHandle phContext)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_FreeContextBuffer(void* pvContextBuffer)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_ImpersonateSecurityContext(PCtxtHandle phContext)
{
	wStream* s;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_IMPERSONATE_SECURITY_CONTEXT_REQ req;
	NETSSPI_IMPERSONATE_SECURITY_CONTEXT_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	hdr_req.FunctionId = NETSSPI_IMPERSONATE_SECURITY_CONTEXT;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 16;

	req.Context.dwLower = (UINT64) phContext->dwLower;
	req.Context.dwUpper = (UINT64) phContext->dwUpper;

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	netsspi_write_handle(s, &req.Context);

	/* Step 3: Send */

	context->Write(context, Stream_Buffer(s), Stream_GetPosition(s));
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	/* Step 6: Deallocate */

	return hdr_rsp.Status;
}

SECURITY_STATUS SEC_ENTRY netsspi_InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext,
		SEC_WCHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
		PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
		PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_InitializeSecurityContextA(PCredHandle phCredential, PCtxtHandle phContext,
		SEC_CHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
		PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
		PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_QueryContextAttributesX(PCtxtHandle phContext, ULONG ulAttribute, void* pBuffer, UINT16 encoding)
{
	wStream* s;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_QUERY_CONTEXT_ATTRIBUTES_REQ req;
	NETSSPI_QUERY_CONTEXT_ATTRIBUTES_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	hdr_req.FunctionId = NETSSPI_QUERY_CONTEXT_ATTRIBUTES;
	hdr_req.Flags = (encoding == NETSSPI_STRING_UNICODE) ? NETSSPI_FLAGS_UNICODE : 0;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 16 + 4;

	req.Context.dwLower = (UINT64) phContext->dwLower;
	req.Context.dwUpper = (UINT64) phContext->dwUpper;

	req.ulAttribute = (UINT32) ulAttribute;

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	netsspi_write_handle(s, &(req.Context));
	Stream_Write_UINT32(s, req.ulAttribute);

	/* Step 3: Send */

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	Stream_Read_UINT32(s, rsp.Length);

	if (rsp.Length > 0)
	{
		rsp.Buffer = (BYTE*) malloc(rsp.Length);
		Stream_Read(s, rsp.Buffer, rsp.Length);
		CopyMemory(pBuffer, rsp.Buffer, rsp.Length);
		free(rsp.Buffer);
	}

	/* Step 6: Deallocate */

	return hdr_rsp.Status;
}

SECURITY_STATUS SEC_ENTRY netsspi_QueryContextAttributesW(PCtxtHandle phContext, ULONG ulAttribute, void* pBuffer)
{
	return netsspi_QueryContextAttributesX(phContext, ulAttribute, pBuffer, NETSSPI_STRING_UNICODE);
}

SECURITY_STATUS SEC_ENTRY netsspi_QueryContextAttributesA(PCtxtHandle phContext, ULONG ulAttribute, void* pBuffer)
{
	return netsspi_QueryContextAttributesX(phContext, ulAttribute, pBuffer, NETSSPI_STRING_ANSI);
}

SECURITY_STATUS SEC_ENTRY netsspi_QuerySecurityContextToken(PCtxtHandle phContext, HANDLE* phToken)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_SetContextAttributes(PCtxtHandle phContext, ULONG ulAttribute, void* pBuffer, ULONG cbBuffer)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_RevertSecurityContext(PCtxtHandle phContext)
{
	wStream* s;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_REVERT_SECURITY_CONTEXT_REQ req;
	NETSSPI_REVERT_SECURITY_CONTEXT_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	hdr_req.FunctionId = NETSSPI_REVERT_SECURITY_CONTEXT;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 16;

	req.Context.dwLower = (UINT64) phContext->dwLower;
	req.Context.dwUpper = (UINT64) phContext->dwUpper;

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	netsspi_write_handle(s, &req.Context);

	/* Step 3: Send */

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	/* Step 6: Deallocate */

	return hdr_rsp.Status;
}

/* Message Support */

SECURITY_STATUS SEC_ENTRY netsspi_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
	int i;
	wStream* s;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_DECRYPT_MESSAGE_REQ req;
	NETSSPI_DECRYPT_MESSAGE_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	hdr_req.FunctionId = NETSSPI_DECRYPT_MESSAGE;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 16 + 4;

	req.Context.dwLower = (UINT64) phContext->dwLower;
	req.Context.dwUpper = (UINT64) phContext->dwUpper;

	hdr_req.TotalLength += 8;

	req.Message.ulVersion = pMessage->ulVersion;
	req.Message.cBuffers = pMessage->cBuffers;
	req.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * pMessage->cBuffers);

	for (i = 0; i < (int) pMessage->cBuffers; i++)
	{
		req.Message.pBuffers[i].cbBuffer = pMessage->pBuffers[i].cbBuffer;
		req.Message.pBuffers[i].BufferType = pMessage->pBuffers[i].BufferType;
		req.Message.pBuffers[i].pvBuffer = malloc(pMessage->pBuffers[i].cbBuffer);
		CopyMemory(req.Message.pBuffers[i].pvBuffer, pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
		hdr_req.TotalLength += (8 + req.Message.pBuffers[i].cbBuffer);
	}

	req.MessageSeqNo = (UINT32) MessageSeqNo;

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	netsspi_write_handle(s, &(req.Context));

	Stream_Write_UINT32(s, req.Message.ulVersion);
	Stream_Write_UINT32(s, req.Message.cBuffers);

	for (i = 0; i < (int) req.Message.cBuffers; i++)
	{
		Stream_Write_UINT32(s, req.Message.pBuffers[i].cbBuffer);
		Stream_Write_UINT32(s, req.Message.pBuffers[i].BufferType);
		Stream_Write(s, req.Message.pBuffers[i].pvBuffer, req.Message.pBuffers[i].cbBuffer);
	}

	Stream_Write_UINT32(s, req.MessageSeqNo);

	/* Step 3: Send */

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	Stream_Read_UINT32(s, rsp.Message.ulVersion);
	Stream_Read_UINT32(s, rsp.Message.cBuffers);
	rsp.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * rsp.Message.cBuffers);

	for (i = 0; i < (int) rsp.Message.cBuffers; i++)
	{
		Stream_Read_UINT32(s, rsp.Message.pBuffers[i].cbBuffer);
		Stream_Read_UINT32(s, rsp.Message.pBuffers[i].BufferType);
		rsp.Message.pBuffers[i].pvBuffer = malloc(rsp.Message.pBuffers[i].cbBuffer);
		Stream_Read(s, rsp.Message.pBuffers[i].pvBuffer, rsp.Message.pBuffers[i].cbBuffer);
	}

	Stream_Read_UINT32(s, rsp.fQOP);

	for (i = 0; i < (int) rsp.Message.cBuffers; i++)
	{
		pMessage->pBuffers[i].cbBuffer = rsp.Message.pBuffers[i].cbBuffer;
		CopyMemory(pMessage->pBuffers[i].pvBuffer, rsp.Message.pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
	}

	/* Step 6: Deallocate */

	return hdr_rsp.Status;
}

SECURITY_STATUS SEC_ENTRY netsspi_EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
	int i;
	wStream* s;
	NETSSPI_HEADER_REQ hdr_req;
	NETSSPI_HEADER_RSP hdr_rsp;
	NETSSPI_ENCRYPT_MESSAGE_REQ req;
	NETSSPI_ENCRYPT_MESSAGE_RSP rsp;

	/* Step 1: Allocate */

	ZeroMemory(&req, sizeof(req));
	ZeroMemory(&rsp, sizeof(rsp));
	ZeroMemory(&hdr_req, sizeof(hdr_req));
	ZeroMemory(&hdr_rsp, sizeof(hdr_rsp));

	hdr_req.FunctionId = NETSSPI_ENCRYPT_MESSAGE;
	hdr_req.TotalLength = NETSSPI_HEADER_REQ_LENGTH + 32;

	req.Context.dwLower = (UINT64) phContext->dwLower;
	req.Context.dwUpper = (UINT64) phContext->dwUpper;

	req.fQOP = (UINT32) fQOP;

	req.Message.ulVersion = pMessage->ulVersion;
	req.Message.cBuffers = pMessage->cBuffers;
	req.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * pMessage->cBuffers);

	for (i = 0; i < (int) pMessage->cBuffers; i++)
	{
		req.Message.pBuffers[i].cbBuffer = pMessage->pBuffers[i].cbBuffer;
		req.Message.pBuffers[i].BufferType = pMessage->pBuffers[i].BufferType;
		req.Message.pBuffers[i].pvBuffer = malloc(pMessage->pBuffers[i].cbBuffer);
		CopyMemory(req.Message.pBuffers[i].pvBuffer, pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
		hdr_req.TotalLength += (8 + req.Message.pBuffers[i].cbBuffer);
	}

	req.MessageSeqNo = (UINT32) MessageSeqNo;

	s = Stream_New(NULL, hdr_req.TotalLength);

	/* Step 2: Marshal */

	netsspi_write_header_req(s, &hdr_req);

	netsspi_write_handle(s, &(req.Context));

	Stream_Write_UINT32(s, req.fQOP);

	Stream_Write_UINT32(s, req.Message.ulVersion);
	Stream_Write_UINT32(s, req.Message.cBuffers);

	for (i = 0; i < (int) req.Message.cBuffers; i++)
	{
		Stream_Write_UINT32(s, req.Message.pBuffers[i].cbBuffer);
		Stream_Write_UINT32(s, req.Message.pBuffers[i].BufferType);
		Stream_Write(s, req.Message.pBuffers[i].pvBuffer, req.Message.pBuffers[i].cbBuffer);
	}

	Stream_Write_UINT32(s, req.MessageSeqNo);

	/* Step 3: Send */

	netsspi_send_message(context, s);
	Stream_Free(s, TRUE);

	/* Step 4: Receive */

	s = netsspi_recv_message(context);

	/* Step 5: Unmarshal */

	netsspi_read_header_rsp(s, &hdr_rsp);

	Stream_Read_UINT32(s, rsp.Message.ulVersion);
	Stream_Read_UINT32(s, rsp.Message.cBuffers);
	rsp.Message.pBuffers = (NETSSPI_SEC_BUFFER*) malloc(sizeof(NETSSPI_SEC_BUFFER) * rsp.Message.cBuffers);

	for (i = 0; i < (int) rsp.Message.cBuffers; i++)
	{
		Stream_Read_UINT32(s, rsp.Message.pBuffers[i].cbBuffer);
		Stream_Read_UINT32(s, rsp.Message.pBuffers[i].BufferType);
		rsp.Message.pBuffers[i].pvBuffer = malloc(rsp.Message.pBuffers[i].cbBuffer);
		Stream_Read(s, rsp.Message.pBuffers[i].pvBuffer, rsp.Message.pBuffers[i].cbBuffer);
	}

	for (i = 0; i < (int) rsp.Message.cBuffers; i++)
	{
		pMessage->pBuffers[i].cbBuffer = rsp.Message.pBuffers[i].cbBuffer;
		CopyMemory(pMessage->pBuffers[i].pvBuffer, rsp.Message.pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
	}

	/* Step 6: Deallocate */

	return hdr_rsp.Status;
}

SECURITY_STATUS SEC_ENTRY netsspi_MakeSignature(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SECURITY_STATUS SEC_ENTRY netsspi_VerifySignature(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
	return SEC_E_UNSUPPORTED_FUNCTION;
}

SecurityFunctionTableA NETSSPI_SecurityFunctionTableA =
{
	1, /* dwVersion */
	netsspi_EnumerateSecurityPackagesA, /* EnumerateSecurityPackages */
	netsspi_QueryCredentialsAttributesA, /* QueryCredentialsAttributes */
	netsspi_AcquireCredentialsHandleA, /* AcquireCredentialsHandle */
	netsspi_FreeCredentialsHandle, /* FreeCredentialsHandle */
	NULL, /* Reserved2 */
	netsspi_InitializeSecurityContextA, /* InitializeSecurityContext */
	netsspi_AcceptSecurityContext, /* AcceptSecurityContext */
	netsspi_CompleteAuthToken, /* CompleteAuthToken */
	netsspi_DeleteSecurityContext, /* DeleteSecurityContext */
	netsspi_ApplyControlToken, /* ApplyControlToken */
	netsspi_QueryContextAttributesA, /* QueryContextAttributes */
	netsspi_ImpersonateSecurityContext, /* ImpersonateSecurityContext */
	netsspi_RevertSecurityContext, /* RevertSecurityContext */
	netsspi_MakeSignature, /* MakeSignature */
	netsspi_VerifySignature, /* VerifySignature */
	netsspi_FreeContextBuffer, /* FreeContextBuffer */
	netsspi_QuerySecurityPackageInfoA, /* QuerySecurityPackageInfo */
	NULL, /* Reserved3 */
	NULL, /* Reserved4 */
	netsspi_ExportSecurityContext, /* ExportSecurityContext */
	netsspi_ImportSecurityContextA, /* ImportSecurityContext */
	NULL, /* AddCredentials */
	NULL, /* Reserved8 */
	netsspi_QuerySecurityContextToken, /* QuerySecurityContextToken */
	netsspi_EncryptMessage, /* EncryptMessage */
	netsspi_DecryptMessage, /* DecryptMessage */
	netsspi_SetContextAttributes, /* SetContextAttributes */
};

SecurityFunctionTableW NETSSPI_SecurityFunctionTableW =
{
	1, /* dwVersion */
	netsspi_EnumerateSecurityPackagesW, /* EnumerateSecurityPackages */
	netsspi_QueryCredentialsAttributesW, /* QueryCredentialsAttributes */
	netsspi_AcquireCredentialsHandleW, /* AcquireCredentialsHandle */
	netsspi_FreeCredentialsHandle, /* FreeCredentialsHandle */
	NULL, /* Reserved2 */
	netsspi_InitializeSecurityContextW, /* InitializeSecurityContext */
	netsspi_AcceptSecurityContext, /* AcceptSecurityContext */
	netsspi_CompleteAuthToken, /* CompleteAuthToken */
	netsspi_DeleteSecurityContext, /* DeleteSecurityContext */
	netsspi_ApplyControlToken, /* ApplyControlToken */
	netsspi_QueryContextAttributesW, /* QueryContextAttributes */
	netsspi_ImpersonateSecurityContext, /* ImpersonateSecurityContext */
	netsspi_RevertSecurityContext, /* RevertSecurityContext */
	netsspi_MakeSignature, /* MakeSignature */
	netsspi_VerifySignature, /* VerifySignature */
	netsspi_FreeContextBuffer, /* FreeContextBuffer */
	netsspi_QuerySecurityPackageInfoW, /* QuerySecurityPackageInfo */
	NULL, /* Reserved3 */
	NULL, /* Reserved4 */
	netsspi_ExportSecurityContext, /* ExportSecurityContext */
	netsspi_ImportSecurityContextW, /* ImportSecurityContext */
	NULL, /* AddCredentials */
	NULL, /* Reserved8 */
	netsspi_QuerySecurityContextToken, /* QuerySecurityContextToken */
	netsspi_EncryptMessage, /* EncryptMessage */
	netsspi_DecryptMessage, /* DecryptMessage */
	netsspi_SetContextAttributes, /* SetContextAttributes */
};
