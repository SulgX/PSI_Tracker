@echo off
setlocal enabledelayedexpansion
title PSI-Tracker V1.0  DEY IMMORTAL
color 07
mode con: cols=90 lines=40

:: ---------- Capture ESC character for ANSI sequences ----------
for /f "delims=" %%a in ('echo prompt $E^| cmd') do set "ESC=%%a"

:: ============================================================
::                 CONFIGURATION
:: ============================================================
set "SCRIPT=PSI_tracker.py"
set "CONFIG=launcher_settings.ini"

if not exist "%SCRIPT%" (
    echo [ERROR] %SCRIPT% not found. Place this launcher next to the Python script.
    pause & exit /b 1
)
where python >nul 2>&1 || (
    echo [ERROR] Python not found. Install Python 3.7+ and add to PATH.
    pause & exit /b 1
)

:: ----------------------------------------------------------
::  DEFAULT VALUES (overwritten by config file if present)
:: ----------------------------------------------------------
set "LIST_FILE="
set "RANGE_LIST="
set "PORT_LIST="
set "THREADS=50"
set "TIMEOUT=60"
set "TCP_MULT=0.6"
set "AUTH="
set "AUTH_MODE="
set "AUTH_CRED="
set "SSH_HOST=github.com"
set "SSH_PORT=22"
set "ALIVE_FILE=alive_proxies.txt"
set "URLS_FILE=proxy_urls.txt"
set "CHECKPOINT=scan_progress.json"
set "SCOPE="
set "ALLOW_ALL="
set "TARGETS_CFG="
set "FALLBACK_IPS=fallback_ips.json"
set "NO_GEO="
set "NO_DIV="
set "VERBOSE="
set "MAX_ALIVE=0"
set "CLEAN="
set "RETEST="
set "REFRESH="

:: Load previous settings
if exist "%CONFIG%" (
    for /f "usebackq tokens=1,* delims==" %%a in ("%CONFIG%") do set "%%a=%%b"
)

:: Load Auth Mode
if not defined AUTH_MODE (
    if defined AUTH if not "%AUTH%"=="" (
        set "AUTH_MODE=single"
        set "AUTH_CRED=!AUTH!"
    ) else (
        set "AUTH_MODE="
        set "AUTH_CRED="
    )
    set "AUTH="
)

:: ---------- Helpers for "none" ----------
:: Case-insensitive "none" -> treat as empty
goto :menu

:isnone
:: %1 = variable name, sets %~1 to empty if its value equals "none" (case-insensitive)
set "temp_val=!%~1!"
if /i "!temp_val!"=="none" set "%~1="
exit /b

:: ============================================================
::                       MAIN MENU
:: ============================================================
:menu
cls

REM ══════════════════════════════════════════════════════════════════════
REM  CLEAN BANNER (all ASCII, no problematic symbols)
REM ══════════════════════════════════════════════════════════════════════
echo %ESC%[1;36m========================================================================================%ESC%[0m
echo %ESC%[1;36m==%ESC%[0m  %ESC%[1;33;44m   PSI TRACKER   %ESC%[0m    %ESC%[1;36m==%ESC%[0m  %ESC%[1;33mDEY_IMMORTAL V1.0%ESC%[0m                         %ESC%[1;36m==%ESC%[0m
echo %ESC%[1;36m==%ESC%[0m  %ESC%[37mUnbreakable Proxy Auditor for Censored Networks%ESC%[0m              %ESC%[1;36m==%ESC%[0m
echo %ESC%[1;36m========================================================================================%ESC%[0m
echo.

REM --------------------------------------------------------------------
REM  PROFILES
REM --------------------------------------------------------------------
echo %ESC%[33;1mProfiles:%ESC%[0m
echo %ESC%[36m [Q]%ESC%[0m %ESC%[33mQuick Scan%ESC%[0m   (20 threads, 30s, --no-geo --no-diversity)
echo %ESC%[36m [D]%ESC%[0m %ESC%[33mDeep Scan%ESC%[0m    (50 threads, 90s, --verbose)
echo %ESC%[36m [F]%ESC%[0m %ESC%[33mFull Scan%ESC%[0m    (50 threads, 120s, --verbose)
echo %ESC%[36m [C]%ESC%[0m %ESC%[33mCustom Scan%ESC%[0m  (run with current settings, NO questions)
echo %ESC%[36m [A]%ESC%[0m %ESC%[33mAdvanced Custom%ESC%[0m (ask EVERY setting step-by-step)
echo.
echo %ESC%[36m [S]%ESC%[0m %ESC%[32mSave settings%ESC%[0m   %ESC%[36m[L]%ESC%[0m %ESC%[32mLoad defaults%ESC%[0m   %ESC%[36m[H]%ESC%[0m %ESC%[32mHelp%ESC%[0m   %ESC%[36m[X]%ESC%[0m %ESC%[32mExit%ESC%[0m
echo.
echo %ESC%[33;1mCurrent Settings:%ESC%[0m
:: about Auth ?
set "AUTH_DISPLAY=none"
if "%AUTH_MODE%"=="single" set "AUTH_DISPLAY=single: %AUTH_CRED%"
if "%AUTH_MODE%"=="file" set "AUTH_DISPLAY=file: passlist.txt"

echo %ESC%[36m [1]%ESC%[0m  List file           = %ESC%[37m%LIST_FILE%%ESC%[0m
echo %ESC%[36m [2]%ESC%[0m  Range(s)            = %ESC%[37m%RANGE_LIST%%ESC%[0m
echo %ESC%[36m [3]%ESC%[0m  Port(s)             = %ESC%[37m%PORT_LIST%%ESC%[0m
echo %ESC%[36m [4]%ESC%[0m  Threads             = %ESC%[37m%THREADS%%ESC%[0m
echo %ESC%[36m [5]%ESC%[0m  Timeout (sec)       = %ESC%[37m%TIMEOUT%%ESC%[0m
echo %ESC%[36m [6]%ESC%[0m  TCP multiplier      = %ESC%[37m%TCP_MULT%%ESC%[0m
echo %ESC%[36m [7]%ESC%[0m  Auth (user:pass)    = %ESC%[37m!AUTH_DISPLAY!%ESC%[0m
echo %ESC%[36m [8]%ESC%[0m  SSH host            = %ESC%[37m%SSH_HOST%%ESC%[0m
echo %ESC%[36m [9]%ESC%[0m  SSH port            = %ESC%[37m%SSH_PORT%%ESC%[0m
echo %ESC%[36m[10]%ESC%[0m  Alive output        = %ESC%[37m%ALIVE_FILE%%ESC%[0m
echo %ESC%[36m[11]%ESC%[0m  URLs output         = %ESC%[37m%URLS_FILE%%ESC%[0m
echo %ESC%[36m[12]%ESC%[0m  Checkpoint file     = %ESC%[37m%CHECKPOINT%%ESC%[0m
echo %ESC%[36m[13]%ESC%[0m  Scope CIDRs         = %ESC%[37m%SCOPE%%ESC%[0m
echo %ESC%[36m[14]%ESC%[0m  Allow all           = %ESC%[37m%ALLOW_ALL%%ESC%[0m
echo %ESC%[36m[15]%ESC%[0m  Targets config      = %ESC%[37m%TARGETS_CFG%%ESC%[0m
echo %ESC%[36m[16]%ESC%[0m  Fallback IPs        = %ESC%[37m%FALLBACK_IPS%%ESC%[0m
echo %ESC%[36m[17]%ESC%[0m  No GeoIP            = %ESC%[37m%NO_GEO%%ESC%[0m
echo %ESC%[36m[18]%ESC%[0m  No diversity        = %ESC%[37m%NO_DIV%%ESC%[0m
echo %ESC%[36m[19]%ESC%[0m  Verbose             = %ESC%[37m%VERBOSE%%ESC%[0m
echo %ESC%[36m[20]%ESC%[0m  Max alive (stop)    = %ESC%[37m%MAX_ALIVE%%ESC%[0m
echo %ESC%[36m[21]%ESC%[0m  Clean files         = %ESC%[37m%CLEAN%%ESC%[0m
echo %ESC%[36m[22]%ESC%[0m  Retest all          = %ESC%[37m%RETEST%%ESC%[0m
echo %ESC%[36m[23]%ESC%[0m  Refresh fallback    = %ESC%[37m%REFRESH%%ESC%[0m
echo.

REM ---------- foolproof input without stray cursor ----------
echo.
set "opt="
set /p "opt=Choose option: "

:: ----------------------------------------------------------
::  ROUTE USER CHOICE
:: ----------------------------------------------------------
if "%opt%"=="1"  goto set_list
if "%opt%"=="2"  goto set_range
if "%opt%"=="3"  goto set_port
if "%opt%"=="4"  goto set_threads
if "%opt%"=="5"  goto set_timeout
if "%opt%"=="6"  goto set_tcp_mult
if "%opt%"=="7"  goto set_auth
if "%opt%"=="8"  goto set_ssh_host
if "%opt%"=="9"  goto set_ssh_port
if "%opt%"=="10" goto set_alive
if "%opt%"=="11" goto set_urls
if "%opt%"=="12" goto set_checkpoint
if "%opt%"=="13" goto set_scope
if "%opt%"=="14" goto set_allowall
if "%opt%"=="15" goto set_targets
if "%opt%"=="16" goto set_fallback
if "%opt%"=="17" goto set_nogeo
if "%opt%"=="18" goto set_nodiv
if "%opt%"=="19" goto set_verbose
if "%opt%"=="20" goto set_maxalive
if "%opt%"=="21" goto set_clean
if "%opt%"=="22" goto set_retest
if "%opt%"=="23" goto set_refresh

if /i "%opt%"=="Q" goto quick
if /i "%opt%"=="D" goto deep
if /i "%opt%"=="F" goto full
if /i "%opt%"=="C" goto custom
if /i "%opt%"=="A" goto advanced_custom
if /i "%opt%"=="S" goto save
if /i "%opt%"=="L" goto load_default
if /i "%opt%"=="H" goto help
if /i "%opt%"=="X" exit /b 0

echo %ESC%[31mInvalid option. Press any key.%ESC%[0m
pause >nul
goto menu

:: ============================================================
::  INDIVIDUAL SETTERS (preserve current value on empty input)
:: ============================================================
:set_list
echo.
call :isnone LIST_FILE
set /p "LIST_FILE=Enter list file path (type 'none' to disable) [%LIST_FILE%]: "
if "%LIST_FILE%"=="" set "LIST_FILE=none"
call :isnone LIST_FILE
goto menu

:set_range
echo.
set /p "RANGE_LIST=Enter range(s) [%RANGE_LIST%]: "
if "%RANGE_LIST%"=="" set "RANGE_LIST=none"
call :isnone RANGE_LIST
goto menu

:set_port
echo.
set /p "PORT_LIST=Enter port(s) separated by space [%PORT_LIST%]: "
if "%PORT_LIST%"=="" set "PORT_LIST=none"
call :isnone PORT_LIST
goto menu

:set_threads
echo.
set /p "THREADS=Enter number of threads [%THREADS%]: "
if "%THREADS%"=="" set "THREADS=50"
goto menu

:set_timeout
echo.
set /p "TIMEOUT=Enter timeout in seconds [%TIMEOUT%]: "
if "%TIMEOUT%"=="" set "TIMEOUT=60"
goto menu

:set_tcp_mult
echo.
set /p "TCP_MULT=Enter TCP connect multiplier (0.1-1.0) [%TCP_MULT%]: "
if "%TCP_MULT%"=="" set "TCP_MULT=0.6"
goto menu

:set_auth
echo.
echo Current Auth mode: %AUTH_MODE% %AUTH_CRED%
echo   [1] Single credential (user:pass^)
echo   [2] Use passlist.txt in script folder
echo   [3] None (no authentication^)
set /p "auth_choice=Choose [1/2/3] or press Enter to keep: "
if "%auth_choice%"=="1" (
    set /p "new_cred=Enter credentials (user:pass): "
    if not "!new_cred!"=="" (
        set "AUTH_MODE=single"
        set "AUTH_CRED=!new_cred!"
    ) else (
        echo No input, keeping previous.
    )
) else if "%auth_choice%"=="2" (
    set "AUTH_MODE=file"
    set "AUTH_CRED="
) else if "%auth_choice%"=="3" (
    set "AUTH_MODE="
    set "AUTH_CRED="
) else (
    echo Invalid choice, keeping previous.
)
pause >nul
goto menu

:set_ssh_host
echo.
set /p "SSH_HOST=Enter SSH target host [%SSH_HOST%]: "
if "%SSH_HOST%"=="" set "SSH_HOST=github.com"
goto menu

:set_ssh_port
echo.
set /p "SSH_PORT=Enter SSH target port [%SSH_PORT%]: "
if "%SSH_PORT%"=="" set "SSH_PORT=22"
goto menu

:set_alive
echo.
call :isnone ALIVE_FILE
set /p "ALIVE_FILE=Enter alive output file name (type 'none' to disable) [%ALIVE_FILE%]: "
if "%ALIVE_FILE%"=="" set "ALIVE_FILE=none"
call :isnone ALIVE_FILE
goto menu

:set_urls
echo.
call :isnone URLS_FILE
set /p "URLS_FILE=Enter URLs output file name (type 'none' to disable) [%URLS_FILE%]: "
if "%URLS_FILE%"=="" set "URLS_FILE=none"
call :isnone URLS_FILE
goto menu

:set_checkpoint
echo.
call :isnone CHECKPOINT
set /p "CHECKPOINT=Enter checkpoint file name (type 'none' to disable) [%CHECKPOINT%]: "
if "%CHECKPOINT%"=="" set "CHECKPOINT=none"
call :isnone CHECKPOINT
goto menu

:set_scope
echo.
set /p "SCOPE=Enter scope CIDRs (space separated) [%SCOPE%]: "
if "%SCOPE%"=="" set "SCOPE=none"
call :isnone SCOPE
goto menu

:set_allowall
:: Now a yes/no prompt, not toggle
echo.
echo Allow all currently: %ALLOW_ALL%
set /p "allow_yn=Enable --allow-all? [y/N]: "
if /i "!allow_yn!"=="y" (set "ALLOW_ALL=--allow-all") else set "ALLOW_ALL="
goto menu

:set_targets
echo.
call :isnone TARGETS_CFG
set /p "TARGETS_CFG=Enter targets config JSON file (type 'none' to disable) [%TARGETS_CFG%]: "
if "%TARGETS_CFG%"=="" set "TARGETS_CFG=none"
call :isnone TARGETS_CFG
goto menu

:set_fallback
echo.
call :isnone FALLBACK_IPS
set /p "FALLBACK_IPS=Enter fallback IPs JSON file (type 'none' to disable) [%FALLBACK_IPS%]: "
if "%FALLBACK_IPS%"=="" set "FALLBACK_IPS=none"
call :isnone FALLBACK_IPS
goto menu

:set_nogeo
echo.
echo No GeoIP currently: %NO_GEO%
set /p "nogeo_yn=Enable --no-geo? [y/N]: "
if /i "!nogeo_yn!"=="y" (set "NO_GEO=--no-geo") else set "NO_GEO="
goto menu

:set_nodiv
echo.
echo No diversity currently: %NO_DIV%
set /p "nodiv_yn=Enable --no-diversity? [y/N]: "
if /i "!nodiv_yn!"=="y" (set "NO_DIV=--no-diversity") else set "NO_DIV="
goto menu

:set_verbose
echo.
echo Verbose currently: %VERBOSE%
set /p "verbose_yn=Enable --verbose? [y/N]: "
if /i "!verbose_yn!"=="y" (set "VERBOSE=--verbose") else set "VERBOSE="
goto menu

:set_maxalive
echo.
set /p "MAX_ALIVE=Stop after N alive proxies (0=unlimited) [%MAX_ALIVE%]: "
if "%MAX_ALIVE%"=="" set "MAX_ALIVE=0"
goto menu

:set_clean
echo.
echo Clean files currently: %CLEAN%
set /p "clean_yn=Enable --clean? [y/N]: "
if /i "!clean_yn!"=="y" (set "CLEAN=--clean") else set "CLEAN="
goto menu

:set_retest
echo.
echo Retest all currently: %RETEST%
set /p "retest_yn=Enable --retest? [y/N]: "
if /i "!retest_yn!"=="y" (set "RETEST=--retest") else set "RETEST="
goto menu

:set_refresh
echo.
echo Refresh fallback currently: %REFRESH%
set /p "refresh_yn=Enable --refresh-ips? [y/N]: "
if /i "!refresh_yn!"=="y" (set "REFRESH=--refresh-ips") else set "REFRESH="
goto menu

:: ============================================================
::  ADVANCED CUSTOM (step‑by‑step wizard)
:: ============================================================
:advanced_custom
cls
echo ======================== ADVANCED CUSTOM SETUP ========================
echo  (Press Enter to keep the value shown in brackets)
echo.
set /p "LIST_FILE=  1. List file [%LIST_FILE%]: "
set /p "RANGE_LIST=  2. Range(s) [%RANGE_LIST%]: "
set /p "PORT_LIST=  3. Port(s) [%PORT_LIST%]: "

set /p "THREADS=  4. Threads [%THREADS%]: "
if "%THREADS%"=="" set "THREADS=50"

set /p "TIMEOUT=  5. Timeout (sec) [%TIMEOUT%]: "
if "%TIMEOUT%"=="" set "TIMEOUT=60"

set /p "TCP_MULT=  6. TCP multiplier [%TCP_MULT%]: "
if "%TCP_MULT%"=="" set "TCP_MULT=0.6"

echo  7. Auth currently: %AUTH_MODE% %AUTH_CRED%
set /p "AUTH_INPUT=     Enter user:pass, 'file' for passlist.txt, or leave empty for none: "
if /i "!AUTH_INPUT!"=="file" (
    set "AUTH_MODE=file"
    set "AUTH_CRED="
) else if "!AUTH_INPUT!"=="" (
    rem keep current
) else (
    set "AUTH_MODE=single"
    set "AUTH_CRED=!AUTH_INPUT!"
)

set /p "SSH_HOST=  8. SSH host [%SSH_HOST%]: "
if "%SSH_HOST%"=="" set "SSH_HOST=github.com"

set /p "SSH_PORT=  9. SSH port [%SSH_PORT%]: "
if "%SSH_PORT%"=="" set "SSH_PORT=22"

set /p "ALIVE_FILE= 10. Alive output file [%ALIVE_FILE%]: "
if "%ALIVE_FILE%"=="" set "ALIVE_FILE=alive_proxies.txt"

set /p "URLS_FILE= 11. URLs output file [%URLS_FILE%]: "
if "%URLS_FILE%"=="" set "URLS_FILE=proxy_urls.txt"

set /p "CHECKPOINT= 12. Checkpoint file [%CHECKPOINT%]: "
if "%CHECKPOINT%"=="" set "CHECKPOINT=scan_progress.json"

set /p "SCOPE= 13. Scope CIDRs [%SCOPE%]: "
set /p "ALLOW_ALL= 14. Allow all? (--allow-all) [%ALLOW_ALL%]: "
set /p "TARGETS_CFG= 15. Targets config JSON [%TARGETS_CFG%]: "

set /p "FALLBACK_IPS= 16. Fallback IPs file [%FALLBACK_IPS%]: "
if "%FALLBACK_IPS%"=="" set "FALLBACK_IPS=fallback_ips.json"

echo  17. No GeoIP currently: %NO_GEO%
set /p "nogeo_yn=      Enable --no-geo? [y/N]: "
if /i "!nogeo_yn!"=="y" (set "NO_GEO=--no-geo") else set "NO_GEO="

echo  18. No diversity currently: %NO_DIV%
set /p "nodiv_yn=      Enable --no-diversity? [y/N]: "
if /i "!nodiv_yn!"=="y" (set "NO_DIV=--no-diversity") else set "NO_DIV="

echo  19. Verbose currently: %VERBOSE%
set /p "verbose_yn=      Enable --verbose? [y/N]: "
if /i "!verbose_yn!"=="y" (set "VERBOSE=--verbose") else set "VERBOSE="

set /p "MAX_ALIVE= 20. Max alive (0=unlimited) [%MAX_ALIVE%]: "
if "%MAX_ALIVE%"=="" set "MAX_ALIVE=0"

echo  21. Clean files currently: %CLEAN%
set /p "clean_yn=      Enable --clean? [y/N]: "
if /i "!clean_yn!"=="y" (set "CLEAN=--clean") else set "CLEAN="

echo  22. Retest all currently: %RETEST%
set /p "retest_yn=      Enable --retest? [y/N]: "
if /i "!retest_yn!"=="y" (set "RETEST=--retest") else set "RETEST="

echo  23. Refresh fallback currently: %REFRESH%
set /p "refresh_yn=      Enable --refresh-ips? [y/N]: "
if /i "!refresh_yn!"=="y" (set "REFRESH=--refresh-ips") else set "REFRESH="

goto run

:: ============================================================
::  PROFILES
:: ============================================================
:quick
set "THREADS=20"
set "TIMEOUT=30"
set "NO_GEO=--no-geo"
set "NO_DIV=--no-diversity"
set "VERBOSE="
goto run

:deep
set "THREADS=50"
set "TIMEOUT=90"
set "NO_GEO="
set "NO_DIV="
set "VERBOSE=--verbose"
goto run

:full
set "THREADS=50"
set "TIMEOUT=120"
set "NO_GEO="
set "NO_DIV="
set "VERBOSE=--verbose"
goto run

:custom
:: simply use current settings (no changes)
goto run

:: ============================================================
::  BUILD COMMAND & EXECUTE
:: ============================================================
:run
:: First, treat all "none" values as empty
call :isnone LIST_FILE
call :isnone RANGE_LIST
call :isnone PORT_LIST
call :isnone ALIVE_FILE
call :isnone URLS_FILE
call :isnone CHECKPOINT
call :isnone SCOPE
call :isnone TARGETS_CFG
call :isnone FALLBACK_IPS

if "%REFRESH%"=="--refresh-ips" goto execute
if "%LIST_FILE%"=="" if "%RANGE_LIST%"=="" (
    echo %ESC%[31m[ERROR] You must specify a list file [1] or a range [2].%ESC%[0m
    pause
    goto menu
)
if not "%LIST_FILE%"=="" if not exist "%LIST_FILE%" (
    echo %ESC%[31m[ERROR] List file "%LIST_FILE%" not found.%ESC%[0m
    pause
    goto menu
)

:execute
set "CMD=python "%SCRIPT%""
if not "%LIST_FILE%"==""   set "CMD=!CMD! --list "%LIST_FILE%""
if not "%RANGE_LIST%"==""  set "CMD=!CMD! --range "%RANGE_LIST%""
if not "%PORT_LIST%"==""   set "CMD=!CMD! --port %PORT_LIST%"
set "CMD=!CMD! --threads %THREADS% --timeout %TIMEOUT%"
if not "%TCP_MULT%"==""    set "CMD=!CMD! --tcp-timeout-mult %TCP_MULT%"
:: Auth: only pass --auth if single mode and credentials exist
if "%AUTH_MODE%"=="single" if not "%AUTH_CRED%"=="" set "CMD=!CMD! --auth "%AUTH_CRED%""
if not "%SSH_HOST%"==""    set "CMD=!CMD! --ssh-host %SSH_HOST%"
if not "%SSH_PORT%"==""    set "CMD=!CMD! --ssh-port %SSH_PORT%"
if not "%ALIVE_FILE%"==""  set "CMD=!CMD! --alive "%ALIVE_FILE%""
if not "%URLS_FILE%"==""   set "CMD=!CMD! --urls "%URLS_FILE%""
if not "%CHECKPOINT%"==""  set "CMD=!CMD! --checkpoint "%CHECKPOINT%""
if not "%SCOPE%"==""       set "CMD=!CMD! --scope %SCOPE%"
if "%ALLOW_ALL%"=="--allow-all" set "CMD=!CMD! --allow-all"
if not "%TARGETS_CFG%"=="" set "CMD=!CMD! --targets-config "%TARGETS_CFG%""
if not "%FALLBACK_IPS%"=="" set "CMD=!CMD! --fallback-ips "%FALLBACK_IPS%""
if "%NO_GEO%"=="--no-geo"   set "CMD=!CMD! --no-geo"
if "%NO_DIV%"=="--no-diversity" set "CMD=!CMD! --no-diversity"
if "%VERBOSE%"=="--verbose" set "CMD=!CMD! --verbose"
if %MAX_ALIVE% gtr 0        set "CMD=!CMD! --max-alive %MAX_ALIVE%"
if "%CLEAN%"=="--clean"     set "CMD=!CMD! --clean"
if "%RETEST%"=="--retest"   set "CMD=!CMD! --retest"
if "%REFRESH%"=="--refresh-ips" set "CMD=!CMD! --refresh-ips"

echo.
echo %ESC%[33m===============================================================================%ESC%[0m
echo %ESC%[33m  Running PSI-Tracker...%ESC%[0m
echo %ESC%[33m===============================================================================%ESC%[0m
echo  !CMD!
echo.
echo %ESC%[36m  [TIP] Press P to pause, R to resume, M to abort and return to menu.%ESC%[0m
pause
%CMD%
echo %ESC%[32mScan finished. Press any key to return to menu.%ESC%[0m
pause >nul
goto menu

:: ============================================================
::  SAVE / LOAD / HELP
:: ============================================================
:save
(
echo LIST_FILE=%LIST_FILE%
echo RANGE_LIST=%RANGE_LIST%
echo PORT_LIST=%PORT_LIST%
echo THREADS=%THREADS%
echo TIMEOUT=%TIMEOUT%
echo TCP_MULT=%TCP_MULT%
echo AUTH_MODE=%AUTH_MODE%
echo AUTH_CRED=%AUTH_CRED%
echo SSH_HOST=%SSH_HOST%
echo SSH_PORT=%SSH_PORT%
echo ALIVE_FILE=%ALIVE_FILE%
echo URLS_FILE=%URLS_FILE%
echo CHECKPOINT=%CHECKPOINT%
echo SCOPE=%SCOPE%
echo ALLOW_ALL=%ALLOW_ALL%
echo TARGETS_CFG=%TARGETS_CFG%
echo FALLBACK_IPS=%FALLBACK_IPS%
echo NO_GEO=%NO_GEO%
echo NO_DIV=%NO_DIV%
echo VERBOSE=%VERBOSE%
echo MAX_ALIVE=%MAX_ALIVE%
echo CLEAN=%CLEAN%
echo RETEST=%RETEST%
echo REFRESH=%REFRESH%
) > "%CONFIG%"
echo %ESC%[32mSettings saved to %CONFIG%.%ESC%[0m
pause
goto menu

:load_default
set "LIST_FILE="
set "RANGE_LIST="
set "PORT_LIST="
set "THREADS=50"
set "TIMEOUT=60"
set "TCP_MULT=0.6"
set "AUTH="
set "AUTH_MODE="
set "AUTH_CRED="
set "SSH_HOST=github.com"
set "SSH_PORT=22"
set "ALIVE_FILE=alive_proxies.txt"
set "URLS_FILE=proxy_urls.txt"
set "CHECKPOINT=scan_progress.json"
set "SCOPE="
set "ALLOW_ALL="
set "TARGETS_CFG="
set "FALLBACK_IPS=fallback_ips.json"
set "NO_GEO="
set "NO_DIV="
set "VERBOSE="
set "MAX_ALIVE=0"
set "CLEAN="
set "RETEST="
set "REFRESH="
echo %ESC%[32mDefault settings loaded.%ESC%[0m
pause
goto menu

:help
cls
echo %ESC%[33;1m======================== HELP ========================%ESC%[0m
echo %ESC%[36mPSI-Tracker V1.0 "DEY_IMMORTAL" - Full Argument Reference%ESC%[0m
echo.
echo %ESC%[37m--list FILE            Target file (IP:PORT, CIDR, dash range)%ESC%[0m
echo %ESC%[37m--range RANGE          CIDR or dash ranges%ESC%[0m
echo %ESC%[37m--port PORT [PORT]     Port(s) for IPs without port%ESC%[0m
echo %ESC%[37m--threads N            Threads (default 50)%ESC%[0m
echo %ESC%[37m--timeout SECONDS      Per-proxy timeout (default 60)%ESC%[0m
echo %ESC%[37m--tcp-timeout-mult X   TCP connect multiplier (default 0.6)%ESC%[0m
echo %ESC%[37m--auth USER:PASS       Credentials for auth-requiring proxies%ESC%[0m
echo %ESC%[37m--ssh-host HOST        SSH target host (default github.com)%ESC%[0m
echo %ESC%[37m--ssh-port PORT        SSH target port (default 22)%ESC%[0m
echo %ESC%[37m--alive FILE           Output file for alive proxies with details%ESC%[0m
echo %ESC%[37m--urls FILE            Output file for proxy URLs%ESC%[0m
echo %ESC%[37m--checkpoint FILE      Progress checkpoint file%ESC%[0m
echo %ESC%[37m--scope CIDR [CIDR]    Restrict range expansion to these CIDRs%ESC%[0m
echo %ESC%[37m--allow-all            Bypass --scope requirement%ESC%[0m
echo %ESC%[37m--targets-config JSON  Custom test targets JSON config%ESC%[0m
echo %ESC%[37m--fallback-ips JSON    Additional fallback IPs JSON file%ESC%[0m
echo %ESC%[37m--clean                Clear output files before start%ESC%[0m
echo %ESC%[37m--retest               Ignore checkpoint and re-test all%ESC%[0m
echo %ESC%[37m--refresh-ips          Re-resolve known hosts ^& update fallback IPs%ESC%[0m
echo %ESC%[37m--no-geo               Disable GeoIP lookup%ESC%[0m
echo %ESC%[37m--no-diversity         Skip port diversity test%ESC%[0m
echo %ESC%[37m--verbose              Detailed console output (full stats)%ESC%[0m
echo %ESC%[37m--max-alive N          Stop after finding N alive proxies%ESC%[0m
echo.
echo %ESC%[33mEXAMPLES:%ESC%[0m
echo   %ESC%[36mBasic scan:%ESC%[0m set list file [1], then press C (Custom)
echo   %ESC%[36mCIDR scan :%ESC%[0m set range [2] and ports [3], then press C
echo   %ESC%[36mFast scan :%ESC%[0m press Q (Quick)
echo.
echo %ESC%[33mNOTES:%ESC%[0m
echo   - All tests go through the proxy itself. No direct internet required.
echo   - Press P and R inside the scan window to pause/resume.
echo   - Output files: alive_proxies.txt (detailed), proxy_urls.txt (ready to use)
pause
goto menu
