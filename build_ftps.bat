@echo off
echo Build FTPS Server support...
gcc -O2 -o ftps_server.exe -I. -I./crypery -I./utilery ./crypery/*.c ./utilery/*.c ftps_server.c ftps.c -DHTTP_NO_GZIP -lws2_32
if %errorlevel% neq 0 (
    echo Build Server FAILED
    exit /b 1
)
echo Build FTPS Client support...
gcc -O2 -o ftps_client.exe -I. -I./crypery -I./utilery ./crypery/*.c ./utilery/*.c ftps_client.c ftps.c -DHTTP_NO_GZIP -lws2_32
if %errorlevel% neq 0 (
    echo Build Client FAILED
    exit /b 1
)
echo Build OK.