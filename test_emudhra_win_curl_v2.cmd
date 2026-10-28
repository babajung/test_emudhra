@echo off
setlocal EnableExtensions EnableDelayedExpansion

chcp 65001 >nul

:: Use a stable timestamp format for the report filename
for /f %%I in ('powershell.exe -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "STAMP=%%I"

if not defined STAMP (
    echo [ERROR] Cannot generate report timestamp.
    exit /b 1
)

set "REPORT=emudhra_tls_report_%STAMP%.csv"
set "OUTFILE=%TEMP%\emudhra_curl_%RANDOM%.out"
set "ERRFILE=%TEMP%\emudhra_curl_%RANDOM%.err"

echo ===================================================
echo  eMudhra TLS Certificate Trust Testing (cURL)
echo ===================================================
echo Report: %REPORT%
echo.

where curl.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl.exe not found.
    exit /b 1
)

:: CSV header
> "%REPORT%" echo URL,CURL_EXIT_CODE,HTTP_STATUS,TLS_VERIFY,SECONDS,RESULT

:: 14 incident endpoints plus one independent control
set "URLS=https://dv-g3b-emudhra.we-have-a-problem.com/ https://dv-g3c-emudhra.we-have-a-problem.com/ https://ov-g3b-emudhra.we-have-a-problem.com/ https://ov-g3c-emudhra.we-have-a-problem.com/ https://ev-g3b-emudhra.we-have-a-problem.com/ https://ev-g3c-emudhra.we-have-a-problem.com/ https://dv-g3b-aaa-emudhra.we-have-a-problem.com/ https://dv-g3c-aaa-emudhra.we-have-a-problem.com/ https://ov-g3b-aaa-emudhra.we-have-a-problem.com/ https://ov-g3c-aaa-emudhra.we-have-a-problem.com/ https://ev-g3b-aaa-emudhra.we-have-a-problem.com/ https://ev-g3c-aaa-emudhra.we-have-a-problem.com/ https://dv-g3b-noct-emudhra.we-have-a-problem.com/ https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/ https://github.com"

for %%U in (%URLS%) do (
    echo Testing: %%U
    call :run_curl_test "%%U"
    timeout /t 1 /nobreak >nul
)

del "%OUTFILE%" "%ERRFILE%" >nul 2>&1

echo.
echo Testing completed.
echo Report saved to: %REPORT%
pause
exit /b 0


:run_curl_test
set "CURRENT_URL=%~1"
set "CURL_OUTPUT="
set "CURL_ERR_MSG="
set "CURL_EXIT=0"
set "HTTP_CODE=000"
set "ELAPSED="
set "VERIFY_RESULT="
set "TLS_VERIFY=NOT_VERIFIED"
set "RESULT=NETWORK_OR_TLS_ERROR"

del "%OUTFILE%" "%ERRFILE%" >nul 2>&1

:: Keep curl stdout, stderr, and exit code separate.
:: Do NOT use --insecure or -k.
curl.exe --silent --show-error ^
    --connect-timeout 10 ^
    --max-time 20 ^
    --output nul ^
    --write-out "%%{http_code},%%{time_total},%%{ssl_verify_result}" ^
    "%CURRENT_URL%" >"%OUTFILE%" 2>"%ERRFILE%"

set "CURL_EXIT=!ERRORLEVEL!"

:: Read the structured write-out fields
if exist "%OUTFILE%" (
    set /p "CURL_OUTPUT="<"%OUTFILE%"
)

for /f "tokens=1-3 delims=," %%A in ("!CURL_OUTPUT!") do (
    set "HTTP_CODE=%%A"
    set "ELAPSED=%%B"
    set "VERIFY_RESULT=%%C"
)

:: Read the first stderr line for console diagnostics
if exist "%ERRFILE%" (
    for /f "usebackq delims=" %%I in ("%ERRFILE%") do (
        if not defined CURL_ERR_MSG set "CURL_ERR_MSG=%%I"
    )
)

:: Classify the result. curl exit code 0 means the TLS
:: verification passed and the HTTP request completed,
:: unless other curl options or backend behavior intervene.
if "!CURL_EXIT!"=="0" (
    if "!VERIFY_RESULT!"=="0" (
        set "TLS_VERIFY=PASS"

        if /I "!CURRENT_URL!"=="https://github.com" (
            set "RESULT=CONTROL_OK"
        ) else (
            set "RESULT=TRUSTED_CHAIN"
        )
    ) else (
        set "TLS_VERIFY=CHECK"
        set "RESULT=INCONSISTENT_TLS_RESULT"
    )
) else (
    set "TLS_VERIFY=FAIL"

    :: Explicit certificate / revocation errors only.
    findstr /I ^
        /C:"certificate" ^
        /C:"revoked" ^
        /C:"0x80092010" ^
        /C:"CERT_TRUST" ^
        "%ERRFILE%" >nul 2>&1

    if not errorlevel 1 (
        set "RESULT=CERT_REJECTED"
    ) else (
        findstr /I ^
            /C:"Could not resolve" ^
            /C:"resolve host" ^
            /C:"Name or service not known" ^
            "%ERRFILE%" >nul 2>&1

        if not errorlevel 1 (
            set "RESULT=DNS_ERROR"
        ) else (
            findstr /I ^
                /C:"timed out" ^
                /C:"Timeout was reached" ^
                "%ERRFILE%" >nul 2>&1

            if not errorlevel 1 (
                set "RESULT=TIMEOUT"
            ) else (
                set "RESULT=NETWORK_OR_TLS_ERROR"
            )
        )
    )
)

:: Never interpret a successful TLS connection as proof
:: that a compromised certificate is safe.
echo   Exit: !CURL_EXIT! ^| HTTP: !HTTP_CODE! ^| TLS: !TLS_VERIFY! ^| Result: !RESULT!

if defined CURL_ERR_MSG echo   Detail: !CURL_ERR_MSG!
echo.

:: CSV quoting: double any embedded quotation marks
set "CSV_URL=!CURRENT_URL:"=""!"
>>"%REPORT%" echo "!CSV_URL!",!CURL_EXIT!,"!HTTP_CODE!","!TLS_VERIFY!","!ELAPSED!","!RESULT!"

exit /b 0