@echo off
setlocal enabledelayedexpansion
title DEY_IMMORTAL :: PSI-Tracker V1.0 Launcher
color 0A
mode con: cols=90 lines=30

:: ============================================================
::                 CONFIGURATION
:: ============================================================
set "SCRIPT=PSI_tracker.py"
set "CONFIG=launcher_settings.ini"

:: ----------------------------------------------------------
::  PRE‑CHECKS
:: ----------------------------------------------------------
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

:: ============================================================
::                       MAIN MENU
:: ============================================================
:menu
cls
echo ===============================================================================
echo               PSI-Tracker V1.0 "DEY_IMMORTAL" - Main Menu
echo ===============================================================================
echo  Current Settings:
echo  [1]  List file           = %LIST_FILE%
echo  [2]  Range(s)            = %RANGE_LIST%
echo  [3]  Port(s)             = %PORT_LIST%
echo  [4]  Threads             = %THREADS%
echo  [5]  Timeout (sec)       = %TIMEOUT%
echo  [6]  TCP multiplier      = %TCP_MULT%
echo  [7]  Auth (user:pass)    = %AUTH%
echo  [8]  SSH host            = %SSH_HOST%
echo  [9]  SSH port            = %SSH_PORT%
echo  [10] Alive output        = %ALIVE_FILE%
echo  [11] URLs output         = %URLS_FILE%
echo  [12] Checkpoint file     = %CHECKPOINT%
echo  [13] Scope CIDRs         = %SCOPE%
echo  [14] Allow all           = %ALLOW_ALL%
echo  [15] Targets config      = %TARGETS_CFG%
echo  [16] Fallback IPs        = %FALLBACK_IPS%
echo  [17] No GeoIP            = %NO_GEO%
echo  [18] No diversity        = %NO_DIV%
echo  [19] Verbose             = %VERBOSE%
echo  [20] Max alive (stop)    = %MAX_ALIVE%
echo  [21] Clean files         = %CLEAN%
echo  [22] Retest all          = %RETEST%
echo  [23] Refresh fallback    = %REFRESH%
echo.
echo  Profiles:
echo  [Q] Quick Scan   (20 threads, 30s, --no-geo --no-diversity)
echo  [D] Deep Scan    (50 threads, 90s, --verbose)
echo  [F] Full Scan    (50 threads, 120s, --verbose)
echo  [C] Custom Scan  (run with current settings, NO questions)
echo  [A] Advanced Custom (ask EVERY setting step-by-step)
echo.
echo  [S] Save settings   [L] Load defaults   [H] Help   [X] Exit
echo.
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

echo Invalid option. Press any key.
pause >nul
goto menu

:: ============================================================
::  INDIVIDUAL SETTERS (each returns to menu)
:: ============================================================
:set_list
echo.
set /p "LIST_FILE=Enter list file path [%LIST_FILE%]: "
goto menu

:set_range
echo.
set /p "RANGE_LIST=Enter range(s) (e.g., 192.168.1.0/24 or 1.1.1.1-2.2.2.2) [%RANGE_LIST%]: "
goto menu

:set_port
echo.
set /p "PORT_LIST=Enter port(s) separated by space [%PORT_LIST%]: "
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
set /p "AUTH=Enter credentials (user:pass) or leave empty [%AUTH%]: "
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
set /p "ALIVE_FILE=Enter alive output file name [%ALIVE_FILE%]: "
if "%ALIVE_FILE%"=="" set "ALIVE_FILE=alive_proxies.txt"
goto menu

:set_urls
echo.
set /p "URLS_FILE=Enter URLs output file name [%URLS_FILE%]: "
if "%URLS_FILE%"=="" set "URLS_FILE=proxy_urls.txt"
goto menu

:set_checkpoint
echo.
set /p "CHECKPOINT=Enter checkpoint file name [%CHECKPOINT%]: "
if "%CHECKPOINT%"=="" set "CHECKPOINT=scan_progress.json"
goto menu

:set_scope
echo.
set /p "SCOPE=Enter scope CIDRs (space separated) [%SCOPE%]: "
goto menu

:set_allowall
if "%ALLOW_ALL%"=="--allow-all" (set "ALLOW_ALL=") else set "ALLOW_ALL=--allow-all"
echo Allow all is now: %ALLOW_ALL%
pause
goto menu

:set_targets
echo.
set /p "TARGETS_CFG=Enter targets config JSON file (or empty) [%TARGETS_CFG%]: "
goto menu

:set_fallback
echo.
set /p "FALLBACK_IPS=Enter fallback IPs JSON file [%FALLBACK_IPS%]: "
if "%FALLBACK_IPS%"=="" set "FALLBACK_IPS=fallback_ips.json"
goto menu

:set_nogeo
if "%NO_GEO%"=="--no-geo" (set "NO_GEO=") else set "NO_GEO=--no-geo"
echo No GeoIP is now: %NO_GEO%
pause
goto menu

:set_nodiv
if "%NO_DIV%"=="--no-diversity" (set "NO_DIV=") else set "NO_DIV=--no-diversity"
echo No diversity is now: %NO_DIV%
pause
goto menu

:set_verbose
if "%VERBOSE%"=="--verbose" (set "VERBOSE=") else set "VERBOSE=--verbose"
echo Verbose is now: %VERBOSE%
pause
goto menu

:set_maxalive
echo.
set /p "MAX_ALIVE=Stop after N alive proxies (0=unlimited) [%MAX_ALIVE%]: "
if "%MAX_ALIVE%"=="" set "MAX_ALIVE=0"
goto menu

:set_clean
if "%CLEAN%"=="--clean" (set "CLEAN=") else set "CLEAN=--clean"
echo Clean files is now: %CLEAN%
pause
goto menu

:set_retest
if "%RETEST%"=="--retest" (set "RETEST=") else set "RETEST=--retest"
echo Retest all is now: %RETEST%
pause
goto menu

:set_refresh
if "%REFRESH%"=="--refresh-ips" (set "REFRESH=") else set "REFRESH=--refresh-ips"
echo Refresh fallback is now: %REFRESH%
pause
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

set /p "AUTH=  7. Auth (user:pass) [%AUTH%]: "

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

:: Toggles
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
if "%REFRESH%"=="--refresh-ips" goto execute
if "%LIST_FILE%"=="" if "%RANGE_LIST%"=="" (
    echo [ERROR] You must specify a list file [1] or a range [2].
    pause
    goto menu
)
if not "%LIST_FILE%"=="" if not exist "%LIST_FILE%" (
    echo [ERROR] List file "%LIST_FILE%" not found.
    pause
    goto menu
)

:execute
set "CMD=python "%SCRIPT%""
if not "%LIST_FILE%"=="" set "CMD=!CMD! --list "%LIST_FILE%""
if not "%RANGE_LIST%"=="" set "CMD=!CMD! --range "%RANGE_LIST%""
if not "%PORT_LIST%"=="" set "CMD=!CMD! --port %PORT_LIST%"
set "CMD=!CMD! --threads %THREADS% --timeout %TIMEOUT%"
if not "%TCP_MULT%"=="" set "CMD=!CMD! --tcp-timeout-mult %TCP_MULT%"
if not "%AUTH%"=="" set "CMD=!CMD! --auth "%AUTH%""
if not "%SSH_HOST%"=="" set "CMD=!CMD! --ssh-host %SSH_HOST%"
if not "%SSH_PORT%"=="" set "CMD=!CMD! --ssh-port %SSH_PORT%"
if not "%ALIVE_FILE%"=="" set "CMD=!CMD! --alive "%ALIVE_FILE%""
if not "%URLS_FILE%"=="" set "CMD=!CMD! --urls "%URLS_FILE%""
if not "%CHECKPOINT%"=="" set "CMD=!CMD! --checkpoint "%CHECKPOINT%""
if not "%SCOPE%"=="" set "CMD=!CMD! --scope %SCOPE%"
if "%ALLOW_ALL%"=="--allow-all" set "CMD=!CMD! --allow-all"
if not "%TARGETS_CFG%"=="" set "CMD=!CMD! --targets-config "%TARGETS_CFG%""
if not "%FALLBACK_IPS%"=="" set "CMD=!CMD! --fallback-ips "%FALLBACK_IPS%""
if "%NO_GEO%"=="--no-geo" set "CMD=!CMD! --no-geo"
if "%NO_DIV%"=="--no-diversity" set "CMD=!CMD! --no-diversity"
if "%VERBOSE%"=="--verbose" set "CMD=!CMD! --verbose"
if %MAX_ALIVE% gtr 0 set "CMD=!CMD! --max-alive %MAX_ALIVE%"
if "%CLEAN%"=="--clean" set "CMD=!CMD! --clean"
if "%RETEST%"=="--retest" set "CMD=!CMD! --retest"
if "%REFRESH%"=="--refresh-ips" set "CMD=!CMD! --refresh-ips"

echo.
echo ===============================================================================
echo  Running PSI-Tracker...
echo ===============================================================================
echo  !CMD!
echo.
echo  [TIP] Press P to pause, R to resume during scan.
pause
%CMD%
echo Scan finished. Press any key to return to menu.
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
echo AUTH=%AUTH%
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
echo Settings saved to %CONFIG%.
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
echo Default settings loaded.
pause
goto menu

:help
cls
echo ======================== HELP ========================
echo PSI-Tracker V1.0 "DEY_IMMORTAL" - Full Argument Reference
echo.
echo --list FILE            Target file (IP:PORT, CIDR, dash range)
echo --range RANGE          CIDR or dash ranges
echo --port PORT [PORT]     Port(s) for IPs without port
echo --threads N            Threads (default 50)
echo --timeout SECONDS      Per-proxy timeout (default 60)
echo --tcp-timeout-mult X   TCP connect multiplier (default 0.6)
echo --auth USER:PASS       Credentials for auth-requiring proxies
echo --ssh-host HOST        SSH target host (default github.com)
echo --ssh-port PORT        SSH target port (default 22)
echo --alive FILE           Output file for alive proxies with details
echo --urls FILE            Output file for proxy URLs
echo --checkpoint FILE      Progress checkpoint file
echo --scope CIDR [CIDR]    Restrict range expansion to these CIDRs
echo --allow-all            Bypass --scope requirement
echo --targets-config JSON  Custom test targets JSON config
echo --fallback-ips JSON    Additional fallback IPs JSON file
echo --clean                Clear output files before start
echo --retest               Ignore checkpoint and re-test all
echo --refresh-ips          Re-resolve known hosts & update fallback IPs
echo --no-geo               Disable GeoIP lookup
echo --no-diversity         Skip port diversity test
echo --verbose              Detailed console output (full stats)
echo --max-alive N          Stop after finding N alive proxies
echo.
echo EXAMPLES:
echo   Basic scan: set list file [1], then press C (Custom)
echo   CIDR scan : set range [2] and ports [3], then press C
echo   Fast scan : press Q (Quick)
echo.
echo NOTES:
echo   - All tests go through the proxy itself. No direct internet required.
echo   - Press P and R inside the scan window to pause/resume.
echo   - Output files: alive_proxies.txt (detailed), proxy_urls.txt (ready to use)
pause
goto menu
