// winhttptest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
    BOOL  bResults = FALSE;
    
    LPCWSTR pszUrl = L"http://www.google.com/webhp?rls=ig";

    if(argc > 1){
      pszUrl = argv[1];
    }

    {
      WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyInfoIE;

      bResults = WinHttpGetIEProxyConfigForCurrentUser(&proxyInfoIE);

      printf("IE Proxy auto config url: %S\n", proxyInfoIE.lpszAutoConfigUrl);
      printf("IE Proxy: %S\n", proxyInfoIE.lpszProxy);
      printf("IE Proxy bypass: %S\n", proxyInfoIE.lpszProxyBypass);
      
      GlobalFree(proxyInfoIE.lpszAutoConfigUrl);
      GlobalFree(proxyInfoIE.lpszProxy);
      GlobalFree(proxyInfoIE.lpszProxyBypass);

      printf("\n");
    }

    {
      WINHTTP_PROXY_INFO proxyInfo;

      // Retrieve the default proxy configuration.
      bResults = WinHttpGetDefaultProxyConfiguration(&proxyInfo );

      printf("WinHTTP proxy server list: %S\n", proxyInfo.lpszProxy);
      printf("WinHTTP proxy bypass list: %S\n", proxyInfo.lpszProxyBypass);

      GlobalFree( proxyInfo.lpszProxy );
      GlobalFree( proxyInfo.lpszProxyBypass );

      printf("\n");
    }

    {
      wprintf(L"Url: %s", pszUrl);

      URL_COMPONENTS urlComp = {0};
      urlComp.dwStructSize = sizeof(urlComp);

      WCHAR hostname[255]       = L"";
      urlComp.lpszHostName      = hostname;
      urlComp.dwHostNameLength  = ARRAYSIZE(hostname);

      // Set required component lengths to non-zero so that they are cracked.
      urlComp.dwSchemeLength    = (DWORD)-1;
      urlComp.dwUrlPathLength   = (DWORD)-1;
      urlComp.dwExtraInfoLength = (DWORD)-1;

      bResults = WinHttpCrackUrl(pszUrl, (DWORD)wcslen(pszUrl), 0, &urlComp);

      if(!bResults){
        printf("Failed to crach url. Error %d has occurred.\n", GetLastError());
      }

      HINTERNET hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

      // Use WinHttpOpen to obtain a session handle.
      hSession = WinHttpOpen(
        L"winhttptest", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 
        0);

      if(NULL == hSession){
        printf("Failed to create session. Error %d has occurred.\n", GetLastError());
        return -1;
      }

      hConnect = WinHttpConnect(
        hSession, 
        urlComp.lpszHostName,
        INTERNET_DEFAULT_HTTP_PORT, 
        0);

      if(NULL == hConnect){
        printf("Failed to create connection. Error %d has occurred.\n", GetLastError());
        return -1;
      }

      hRequest = WinHttpOpenRequest(
        hConnect, 
        L"GET", 
        urlComp.lpszUrlPath,
        NULL, 
        WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

      if(NULL == hRequest){
        printf("Failed to create request. Error %d has occurred.\n", GetLastError());
        return -1;
      }

      bResults = WinHttpSendRequest(
        hRequest, 
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0, 
        WINHTTP_NO_REQUEST_DATA, 
        0, 
        0, 
        0);

      if(!bResults){
        printf("Failed to send request. Error %d has occurred.\n", GetLastError());
        return -1;
      }

      bResults = WinHttpReceiveResponse(hRequest, NULL);

      if(!bResults){
        printf("Failed to receive response. Error %d has occurred.\n", GetLastError());
        return -1;
      }

      DWORD dwSize = 0;

      bResults = WinHttpQueryHeaders(
        hRequest, 
        WINHTTP_QUERY_RAW_HEADERS_CRLF,
        WINHTTP_HEADER_NAME_BY_INDEX, 
        NULL, 
        &dwSize, 
        WINHTTP_NO_HEADER_INDEX);
      //TODO: find the error code used when queried for size
      //if(ERROR_WINHTTP_HEADER_NOT_FOUND != bResults){
      //    printf("Failed to query headers. Error %d has occurred.\n", GetLastError());
      //    return -1;
      //}

      WCHAR* lpOutBuffer = new WCHAR[ dwSize / sizeof(WCHAR) ];

      bResults = WinHttpQueryHeaders(
        hRequest, 
        WINHTTP_QUERY_RAW_HEADERS_CRLF,
        WINHTTP_HEADER_NAME_BY_INDEX, 
        lpOutBuffer,
        &dwSize, 
        WINHTTP_NO_HEADER_INDEX);

      if(!bResults){
        printf("Failed to query headers. Error %d has occurred.\n", GetLastError());
        return -1;
      }

      printf("Headers:\n%");
      wprintf(lpOutBuffer);

      delete[] lpOutBuffer;

      printf("Body:\n%");
      do{
        bResults = WinHttpQueryDataAvailable(hRequest, &dwSize);
        if(!bResults){
          printf("Failed to query data available. Error %d has occurred.\n", GetLastError());
          return -1;
        }

        if(!dwSize)
          break;

        DWORD dwAllocSize = dwSize+1;
        char* pszOutBuffer = new char[dwAllocSize];
        if(!pszOutBuffer){
          printf("Failed to allocate %d bytes of memory.\n", dwAllocSize);
          break;
        }

        ZeroMemory(pszOutBuffer, dwAllocSize);

        DWORD dwDownloaded = 0;
        bResults = WinHttpReadData(
          hRequest, 
          (LPVOID)pszOutBuffer,
          dwSize, 
          &dwDownloaded);

        if(!bResults){
          printf("Failed to read. Error %d has occurred.\n", GetLastError());
          break;
        }

        //TODO: Note this actually dependes on the encoding of the content
        printf("%*s", dwDownloaded, pszOutBuffer);

        delete[] pszOutBuffer;
      }while(dwSize > 0);

      // Close any open handles.
      if(hRequest) WinHttpCloseHandle(hRequest);
      if(hConnect) WinHttpCloseHandle(hConnect);
      if(hSession) WinHttpCloseHandle(hSession);
    }
}

