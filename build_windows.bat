@echo off
cl /EHsc /W4 /O2 tcpclient.cpp
if errorlevel 1 exit /b 1
cl /EHsc /W4 /O2 tcpserver.cpp
if errorlevel 1 exit /b 1
cl /EHsc /W4 /O2 udpclient.cpp
if errorlevel 1 exit /b 1
cl /EHsc /W4 /O2 udpserver.cpp
if errorlevel 1 exit /b 1
echo Build completed.
