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
#include <winpr/file.h>
#include <winpr/print.h>
#include <winpr/tchar.h>
#include <winpr/stream.h>
#include <winpr/registry.h>

#include "netsspi.h"

#define NETSSPI_PORT	7728

#ifdef _WIN32
#define close(_fd) closesocket(_fd)
#endif

#ifdef _WIN32
#if _WIN32_WINNT < 0x0600
static const char *inet_ntop(int af, const void* src, char* dst, socklen_t cnt)
{
	if (af == AF_INET)
	{
		struct sockaddr_in in;

		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		memcpy(&in.sin_addr, src, sizeof(struct in_addr));
		getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	else if (af == AF_INET6)
	{
		struct sockaddr_in6 in;

		memset(&in, 0, sizeof(in));
		in.sin6_family = AF_INET6;
		memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
		getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
		return dst;
	}
	
	return NULL;
}
#endif
#endif

const char* NETSSPI_FUNCTION_STRINGS[] =
{
	"",
	"EnumerateSecurityPackages",
	"QueryCredentialsAttributes",
	"AcquireCredentialsHandle",
	"FreeCredentialsHandle",
	"Reserved2",
	"InitializeSecurityContext",
	"AcceptSecurityContext",
	"CompleteAuthToken",
	"DeleteSecurityContext",
	"ApplyControlToken",
	"QueryContextAttributes",
	"ImpersonateSecurityContext",
	"RevertSecurityContext",
	"MakeSignature",
	"VerifySignature",
	"FreeContextBuffer",
	"QuerySecurityPackageInfo",
	"Reserved3",
	"Reserved4",
	"ExportSecurityContext",
	"ImportSecurityContext",
	"AddCredentials",
	"Reserved8",
	"QuerySecurityContextToken",
	"EncryptMessage",
	"DecryptMessage",
	"SetContextAttributes"
};

void netsspi_read_header_req(wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	Stream_Read_UINT32(s, hdr_req->TotalLength); /* TotalLength (4 bytes) */
	Stream_Read_UINT8(s, hdr_req->Flags); /* Flags (1 byte) */
	Stream_Read_UINT8(s, hdr_req->FunctionId); /* FunctionId (1 byte) */
	Stream_Read_UINT32(s, hdr_req->ExtFlags); /* ExtFlags (4 bytes) */
}

void netsspi_write_header_req(wStream* s, NETSSPI_HEADER_REQ* hdr_req)
{
	Stream_Write_UINT32(s, hdr_req->TotalLength); /* TotalLength (4 bytes) */
	Stream_Write_UINT8(s, hdr_req->Flags); /* Flags (1 byte) */
	Stream_Write_UINT8(s, hdr_req->FunctionId); /* FunctionId (1 byte) */
	Stream_Write_UINT32(s, hdr_req->ExtFlags); /* ExtFlags (4 bytes) */
}

void netsspi_read_header_rsp(wStream* s, NETSSPI_HEADER_RSP* hdr_rsp)
{
	Stream_Read_UINT32(s, hdr_rsp->TotalLength); /* TotalLength (4 bytes) */
	Stream_Read_UINT8(s, hdr_rsp->Flags); /* Flags (1 byte) */
	Stream_Read_UINT8(s, hdr_rsp->FunctionId); /* FunctionId (1 byte) */
	Stream_Read_UINT32(s, hdr_rsp->ExtFlags); /* ExtFlags (4 bytes) */
	Stream_Read_UINT32(s, hdr_rsp->Status); /* Status (4 bytes) */
}

void netsspi_write_header_rsp(wStream* s, NETSSPI_HEADER_RSP* hdr_rsp)
{
	Stream_Write_UINT32(s, hdr_rsp->TotalLength); /* TotalLength (4 bytes) */
	Stream_Write_UINT8(s, hdr_rsp->Flags); /* Flags (1 byte) */
	Stream_Write_UINT8(s, hdr_rsp->FunctionId); /* FunctionId (1 byte) */
	Stream_Write_UINT32(s, hdr_rsp->ExtFlags); /* ExtFlags (4 bytes) */
	Stream_Write_UINT32(s, hdr_rsp->Status); /* Status (4 bytes) */
}

void netsspi_read_handle(wStream* s, NETSSPI_HANDLE* handle)
{
	Stream_Read_UINT64(s, handle->dwLower);
	Stream_Read_UINT64(s, handle->dwUpper);
}

void netsspi_write_handle(wStream* s, NETSSPI_HANDLE* handle)
{
	Stream_Write_UINT64(s, handle->dwLower);
	Stream_Write_UINT64(s, handle->dwUpper);
}

void netsspi_read_timestamp(wStream* s, NETSSPI_TIMESTAMP* timestamp)
{
	Stream_Read_UINT32(s, timestamp->LowPart);
	Stream_Read_UINT32(s, timestamp->HighPart);
}

void netsspi_write_timestamp(wStream* s, NETSSPI_TIMESTAMP* timestamp)
{
	Stream_Write_UINT32(s, timestamp->LowPart);
	Stream_Write_UINT32(s, timestamp->HighPart);
}

int netsspi_string_length(NETSSPI_STRING* string)
{
	UINT16 Length;

	Length = string->Length & NETSSPI_STRING_LENGTH_MASK;

	if (string->Length & NETSSPI_STRING_UNICODE)
		return Length * 2;
	else
		return Length;
}

void netsspi_init_string(NETSSPI_STRING* string, BYTE* buffer, UINT16 encoding)
{
	UINT16 length;

	if (encoding == NETSSPI_STRING_UNICODE)
	{
		length = lstrlenW((WCHAR*) buffer);
		string->Buffer = (BYTE*) _wcsdup((WCHAR*) buffer);
		string->Length = length | NETSSPI_STRING_UNICODE;
	}
	else
	{
		length = lstrlenA((char*) buffer);
		string->Buffer = (BYTE*) _strdup((char*) buffer);
		string->Length = length;
	}
}

void netsspi_init_string_ex(NETSSPI_STRING* string, BYTE* buffer, UINT16 length, UINT16 encoding)
{
	if (encoding == NETSSPI_STRING_UNICODE)
	{
		string->Buffer = (BYTE*) _wcsdup((WCHAR*) buffer);
		string->Length = length | NETSSPI_STRING_UNICODE;
	}
	else
	{
		string->Buffer = (BYTE*) _strdup((char*) buffer);
		string->Length = length;
	}
}

void netsspi_read_string(wStream* s, NETSSPI_STRING* string)
{
	UINT16 Length;

	Stream_Read_UINT16(s, string->Length);

	Length = string->Length & NETSSPI_STRING_LENGTH_MASK;

	if (string->Length & NETSSPI_STRING_UNICODE)
	{
		string->Buffer = (BYTE*) malloc((Length + 1) * 2);
		Stream_Read(s, string->Buffer, Length * 2);
		string->Buffer[(Length * 2)] = '\0';
		string->Buffer[(Length * 2) + 1] = '\0';
	}
	else
	{
		string->Buffer = (BYTE*) malloc(Length + 1);
		Stream_Read(s, string->Buffer, Length);
		string->Buffer[Length] = '\0';
	}
}

void netsspi_write_string(wStream* s, NETSSPI_STRING* string)
{
	UINT16 Length;

	Stream_Write_UINT16(s, string->Length);

	Length = string->Length & NETSSPI_STRING_LENGTH_MASK;

	if (string->Length & NETSSPI_STRING_UNICODE)
		Stream_Write(s, string->Buffer, Length * 2);
	else
		Stream_Write(s, string->Buffer, Length);
}

void netsspi_free_string(NETSSPI_STRING* string)
{
	if (string)
	{
		if (string->Buffer)
			free(string->Buffer);

		string->Buffer = NULL;
		string->Length = 0;
	}
}

void netsspi_send_message(NETSSPI_CONTEXT* context, wStream* s)
{
	int status;
	int position;
	UINT8 FunctionId;
	UINT32 TotalSent;
	UINT32 TotalLength;

	TotalSent = 0;
	position = Stream_GetPosition(s);
	Stream_SetPosition(s, 0);
	Stream_Read_UINT32(s, TotalLength);
	Stream_Seek_UINT8(s);
	Stream_Read_UINT8(s, FunctionId);
	Stream_SetPosition(s, 0);

	if (position != TotalLength)
	{
		printf("TotalLength mismatch: Actual:%d, Expected:%d\n", position, TotalLength);

		TotalLength = position;
		Stream_Write_UINT32(s, TotalLength);
		Stream_SetPosition(s, 0);
	}

	while (Stream_GetPosition(s) < (long) TotalLength)
	{
		status = context->Write(context, Stream_Pointer(s), TotalLength - Stream_GetPosition(s));

		if (status < 1)
			return;

		TotalSent += (UINT32) status;
		Stream_Seek(s, status);
	}

	if (FunctionId > 27)
		printf("Invalid FunctionId: %d\n", FunctionId);

	printf("Sent Message %s (%d):\n", NETSSPI_FUNCTION_STRINGS[FunctionId], TotalLength);
	winpr_HexDump(Stream_Buffer(s), TotalLength);
	printf("\n");
}

wStream* netsspi_recv_message(NETSSPI_CONTEXT* context)
{
	wStream* s;
	int status;
	int position;
	UINT8 FunctionId;
	UINT32 TotalRead;
	UINT32 TotalLength;

	s = Stream_New(NULL, 4096);
	TotalLength = TotalRead = 0;

	while (1)
	{
		status = context->Read(context, Stream_Pointer(s), Stream_Capacity(s) - Stream_GetPosition(s));

		if (status == 0)
		{
			Sleep(100);
			continue;
		}

		if (status < 1)
			return NULL;

		TotalRead += (UINT32) status;
		Stream_Seek(s, status);

		if (TotalRead >= 10)
			break;
	}

	position = Stream_GetPosition(s);
	Stream_SetPosition(s, 0);
	Stream_Read_UINT32(s, TotalLength);
	Stream_Seek_UINT8(s);
	Stream_Read_UINT8(s, FunctionId);
	Stream_SetPosition(s, position);

	Stream_EnsureCapacity(s, TotalLength);

	while (Stream_GetPosition(s) < (long) TotalLength)
	{
		status = context->Read(context, Stream_Pointer(s), TotalLength - Stream_GetPosition(s));

		if (status == 0)
		{
			Sleep(100);
			continue;
		}

		if (status < 1)
			return NULL;

		TotalRead += (UINT32) status;
		Stream_Seek(s, status);
	}

	Stream_SetPosition(s, 0);

	if (FunctionId > 27)
		printf("Invalid FunctionId: %d\n", FunctionId);

	printf("Received Message %s (%d):\n", NETSSPI_FUNCTION_STRINGS[FunctionId], TotalLength);
	winpr_HexDump(Stream_Buffer(s), TotalLength);
	printf("\n");

	return s;
}

int netsspi_socket_read(NETSSPI_CONTEXT* context, BYTE* data, int length)
{
	int status;

#ifndef _WIN32
	status = recv(context->sockfd, data, length, 0);
#else
	status = recv(context->sockfd, (char*) data, length, 0);
#endif

	if (status == 0)
	{
		return -1;
	}
	if (status < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		perror("recv");

		return -1;
	}

	return status;
}

int netsspi_socket_write(NETSSPI_CONTEXT* context, BYTE* data, int length)
{
	int status;

#ifndef _WIN32
	status = send(context->sockfd, data, length, MSG_NOSIGNAL);
#else
	status = send(context->sockfd, (const char*) data, length, 0);
#endif

	if (status < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			status = 0;
		else
			perror("send");
	}

	return status;
}

int netsspi_tcp_socket_server_open(NETSSPI_CONTEXT* context)
{
	int status;
	char buf[50];
	void* sin_addr;
	char* hostname;
	char servname[10];
	struct addrinfo* ai;
	struct addrinfo* res;
	struct addrinfo hints = { 0 };

#ifdef UNICODE
	int length = lstrlenW(context->Target);
	hostname = (char*) malloc(length + 1);
	WideCharToMultiByte(CP_ACP, 0, context->Target, -1, hostname, length, NULL, NULL);
	hostname[length] = '\0';
#else
	hostname = (char*) context->Target;
#endif

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (hostname == NULL)
		hints.ai_flags = AI_PASSIVE;

	sprintf_s(servname, sizeof(servname), "%d", NETSSPI_PORT);
	status = getaddrinfo(hostname, servname, &hints, &res);

	if (status != 0)
	{
#ifdef _WIN32
		_tprintf(_T("getaddrinfo error: %s\n"), gai_strerror(status));
#else
		perror("getaddrinfo");
#endif
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next)
	{
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;

		context->sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (context->sockfd == -1)
		{
			perror("socket");
			continue;
		}

		status = bind(context->sockfd, ai->ai_addr, ai->ai_addrlen);

		if (status != 0)
		{
#ifdef _WIN32
			_tprintf(L"bind() failed with error: %u\n", WSAGetLastError());
			WSACleanup();
#else
			perror("bind");
			close(context->sockfd);
#endif
			continue;
		}

		status = listen(context->sockfd, 10);

		if (status != 0)
		{
			perror("listen");
			close(context->sockfd);
			continue;
		}

		if (ai->ai_family == AF_INET)
			sin_addr = &(((struct sockaddr_in*) ai->ai_addr)->sin_addr);
		else
			sin_addr = &(((struct sockaddr_in6*) ai->ai_addr)->sin6_addr);

		printf("Listening on %s port %s.\n", inet_ntop(ai->ai_family, sin_addr, buf, sizeof(buf)), servname);

		break;
	}

	freeaddrinfo(res);

	return 1;
}

int netsspi_tcp_socket_client_open(NETSSPI_CONTEXT* context)
{
	int status;
	char* hostname;
	char servname[10];
	struct addrinfo* ai;
	struct addrinfo* res;
	struct addrinfo hints = { 0 };

#ifdef UNICODE
	int length = lstrlenW(context->Target);
	hostname = (char*) malloc(length + 1);
	WideCharToMultiByte(CP_ACP, 0, context->Target, -1, hostname, length, NULL, NULL);
	hostname[length] = '\0';
#else
	hostname = (char*) context->Target;
#endif

	ZeroMemory(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	sprintf_s(servname, sizeof(servname), "%d", NETSSPI_PORT);
	status = getaddrinfo(hostname, servname, &hints, &res);

	if (status != 0)
	{
		printf("tcp_connect: getaddrinfo (%s)\n", gai_strerror(status));
		return -1;
	}

	context->sockfd = -1;

	for (ai = res; ai; ai = ai->ai_next)
	{
		context->sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (context->sockfd < 0)
			continue;

		if (connect(context->sockfd, ai->ai_addr, ai->ai_addrlen) == 0)
		{
			printf("connected to %s:%s\n", hostname, servname);
			break;
		}

		close(context->sockfd);
		context->sockfd = -1;
	}

	freeaddrinfo(res);

	if (context->sockfd == -1)
	{
		printf("unable to connect to %s:%s\n", hostname, servname);
		return -1;
	}

	return 1;
}

int netsspi_tcp_socket_open(NETSSPI_CONTEXT* context)
{
	if (context->server)
		return netsspi_tcp_socket_server_open(context);
	else
		return netsspi_tcp_socket_client_open(context);
}

int netsspi_tcp_socket_close(NETSSPI_CONTEXT* context)
{
	return 1;
}

#ifndef _WIN32

int netsspi_ipc_socket_open(NETSSPI_CONTEXT* context)
{
	int status;
	int sockfd;
	struct sockaddr_un addr;

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sockfd == -1)
	{
		perror("socket");
		return -1;
	}

	fcntl(sockfd, F_SETFL, O_NONBLOCK);

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, context->Target, sizeof(addr.sun_path));
	unlink(context->Target);

	status = bind(sockfd, (struct sockaddr*) &addr, sizeof(addr));

	if (status != 0)
	{
		perror("bind");
		close(sockfd);
		return -1;
	}

	status = listen(sockfd, 10);

	if (status != 0)
	{
		perror("listen");
		close(sockfd);
		return -1;
	}

	printf("Listening on socket %s\n", addr.sun_path);

	return sockfd;
}

int netsspi_ipc_socket_connect(NETSSPI_CONTEXT* context)
{
	int status;
	int sockfd;
	struct sockaddr_un addr;

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sockfd == -1)
	{
		perror("socket");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, context->Target, sizeof(addr.sun_path));
	status = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));

	if (status < 0)
	{
		perror("connect");
		close(sockfd);
		return -1;
	}

	context->sockfd = sockfd;

	return 1;
}

int netsspi_ipc_socket_close(NETSSPI_CONTEXT* context)
{
	return 1;
}

#endif

#ifdef _WIN32

int netsspi_serial_device_open(NETSSPI_CONTEXT* context)
{
	DCB dcb;

	context->handle = CreateFile(context->Target, GENERIC_WRITE | GENERIC_READ,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (context->handle == INVALID_HANDLE_VALUE)
	{
		_tprintf(_T("Error opening device %s (%d)\n"), context->Target, GetLastError());
		return -1;
	}

	_tprintf(_T("Successfully opened device %s\n"), context->Target);

	GetCommState(context->handle, &dcb);

	dcb.BaudRate = CBR_9600;
	dcb.ByteSize = 8;
	dcb.Parity = NOPARITY;
	dcb.StopBits = ONESTOPBIT;

	SetCommState(context->handle, &dcb);

	return 1;
}

int netsspi_serial_device_close(NETSSPI_CONTEXT* context)
{
	return CloseHandle(context->handle);
}

int netsspi_serial_device_read(NETSSPI_CONTEXT* context, BYTE* data, int length)
{
	DWORD dwBytesRead = 0;

	if (!ReadFile(context->handle, data, length, &dwBytesRead, NULL))
	{
		DWORD error = GetLastError();

		if (error == ERROR_SEM_TIMEOUT)
			return 0;

		_tprintf(_T("Error reading from device: (%d)\n"), GetLastError());
		return -1;
	}

	return (int) dwBytesRead;
}

int netsspi_serial_device_write(NETSSPI_CONTEXT* context, BYTE* data, int length)
{
	DWORD dwBytesWritten = 0;

	if (!WriteFile(context->handle, data, length, &dwBytesWritten, NULL))
	{
		_tprintf(_T("Error writing to device: (%d)\n"), GetLastError());
		return -1;
	}

	return (int) dwBytesWritten;
}

void netsspi_serial_device_init(NETSSPI_CONTEXT* context)
{
	context->Open = netsspi_serial_device_open;
	context->Close = netsspi_serial_device_close;
	context->Read = netsspi_serial_device_read;
	context->Write = netsspi_serial_device_write;
}

#endif

void netsspi_ipc_socket_init(NETSSPI_CONTEXT* context)
{
#ifndef _WIN32
	context->Open = netsspi_ipc_socket_open;
	context->Close = netsspi_ipc_socket_close;
#endif
	context->Read = netsspi_socket_read;
	context->Write = netsspi_socket_write;
}

void netsspi_tcp_socket_init(NETSSPI_CONTEXT* context)
{
	context->Open = netsspi_tcp_socket_open;
	context->Close = netsspi_tcp_socket_close;
	context->Read = netsspi_socket_read;
	context->Write = netsspi_socket_write;
}

NETSSPI_CONTEXT* netsspi_new(BOOL server)
{
	NETSSPI_CONTEXT* context = (NETSSPI_CONTEXT*) malloc(sizeof(NETSSPI_CONTEXT));

	if (context)
	{
		HKEY hKey;
		LONG status;
		DWORD dwType;
		DWORD dwSize;

		ZeroMemory(context, sizeof(NETSSPI_CONTEXT));

		context->server = server;

		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
				(context->server) ? _T("Software\\NetSSPI\\Server") : _T("Software\\NetSSPI\\Client"),
				0, KEY_READ | KEY_WOW64_64KEY, &hKey);

		if (status == ERROR_SUCCESS)
		{
			status = RegQueryValueEx(hKey, _T("Transport"), NULL, &dwType, NULL, &dwSize);

			if (status == ERROR_SUCCESS)
			{
				context->Transport = (LPTSTR) malloc(dwSize + sizeof(TCHAR));

				status = RegQueryValueEx(hKey, _T("Transport"), NULL, &dwType,
						(BYTE*) context->Transport, &dwSize);
			}

			status = RegQueryValueEx(hKey, _T("Target"), NULL, &dwType, NULL, &dwSize);

			if (status == ERROR_SUCCESS)
			{
				context->Target = (LPTSTR) malloc(dwSize + sizeof(TCHAR));

				status = RegQueryValueEx(hKey, _T("Target"), NULL, &dwType,
						(BYTE*) context->Target, &dwSize);
			}

			RegCloseKey(hKey);
		}

		if (!context->Transport)
		{
			context->Transport = _tcsdup(_T("IpcSocket"));
		}

		if (!context->Target)
		{
			context->Target = _tcsdup(_T("/tmp/netsspi0"));
		}

		_tprintf(_T("NetSSPI Transport: %s Target: %s\n"), context->Transport, context->Target);
	}

	return context;
}

void netsspi_free(NETSSPI_CONTEXT* context)
{
	if (context)
	{
		free(context);
	}
}
