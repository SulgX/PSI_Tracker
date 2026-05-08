@echo off
setlocal enabledelayedexpansion
title PSI-TRACKER LAUNCHER
color 0A

:: =====================================================================
::  PSI-TRACKER V1.0 "AEGIS PERFECTA" - RELIABLE LAUNCHER
::  Runs scans in the SAME window so you can use P/R keys.
:: =====================================================================

set "SCRIPT=psi_tracker.py"
set "CONFIG=launcher_settings.ini"

:: Default values
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

:: Load saved settings if exists
if exist "%CONFIG%" (
    for /f "usebackq tokens=1,* delims==" %%a in ("%CONFIG%") do set "%%a=%%b"
)

:: Check Python and script
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.7+ and add to PATH.
    pause
    exit /b 1
)
if not exist "%SCRIPT%" (
    echo [ERROR] %SCRIPT% not found in current folder.
    pause
    exit /b 1
)

:menu
cls
echo ===============================================================================
echo                      PSI-TRACKER V1.0 "AEGIS PERFECTA"
echo ===============================================================================
echo.
echo  [1] List file          : %LIST_FILE%
echo  [2] Range(s)           : %RANGE_LIST%
echo  [3] Port(s)            : %PORT_LIST%
echo  [4] Threads            : %THREADS%
echo  [5] Timeout            : %TIMEOUT% sec
echo  [6] TCP multiplier     : %TCP_MULT%
echo  [7] Auth (user:pass)   : %AUTH%
echo  [8] SSH host:port      : %SSH_HOST%:%SSH_PORT%
echo  [9] Output alive       : %ALIVE_FILE%
echo [10] Output URLs        : %URLS_FILE%
echo [11] Checkpoint         : %CHECKPOINT%
echo [12] Scope CIDRs        : %SCOPE%
echo [13] Allow all          : %ALLOW_ALL%
echo [14] Targets config     : %TARGETS_CFG%
echo [15] Fallback IPs       : %FALLBACK_IPS%
echo [16] No GeoIP           : %NO_GEO%
echo [17] No diversity       : %NO_DIV%
echo [18] Verbose            : %VERBOSE%
echo [19] Max alive (stop)   : %MAX_ALIVE%
echo [20] Clean files        : %CLEAN%
echo [21] Retest all         : %RETEST%
echo [22] Refresh fallback   : %REFRESH%
echo.
echo  [Q] Quick scan  (20 threads, 30s, --no-geo --no-diversity)
echo  [D] Deep scan   (50 threads, 90s, --verbose)
echo  [F] Full scan   (50 threads, 120s, --verbose)
echo  [C] Custom scan (use current settings)
echo  [S] Save current settings
echo  [L] Load default settings
echo  [H] Help
echo  [X] Exit
echo.
set /p "opt=Choose option: "

:: -------------------- Settings --------------------
if /i "%opt%"=="1"  goto set_list
if /i "%opt%"=="2"  goto set_range
if /i "%opt%"=="3"  goto set_port
if /i "%opt%"=="4"  goto set_threads
if /i "%opt%"=="5"  goto set_timeout
if /i "%opt%"=="6"  goto set_tcp_mult
if /i "%opt%"=="7"  goto set_auth
if /i "%opt%"=="8"  goto set_ssh
if /i "%opt%"=="9"  goto set_alive
if /i "%opt%"=="10" goto set_urls
if /i "%opt%"=="11" goto set_checkpoint
if /i "%opt%"=="12" goto set_scope
if /i "%opt%"=="13" goto set_allowall
if /i "%opt%"=="14" goto set_targets
if /i "%opt%"=="15" goto set_fallback
if /i "%opt%"=="16" goto set_nogeo
if /i "%opt%"=="17" goto set_nodiv
if /i "%opt%"=="18" goto set_verbose
if /i "%opt%"=="19" goto set_maxalive
if /i "%opt%"=="20" goto set_clean
if /i "%opt%"=="21" goto set_retest
if /i "%opt%"=="22" goto set_refresh

:: -------------------- Scan profiles --------------------
if /i "%opt%"=="Q" goto quick
if /i "%opt%"=="D" goto deep
if /i "%opt%"=="F" goto full
if /i "%opt%"=="C" goto custom
if /i "%opt%"=="S" goto save
if /i "%opt%"=="L" goto load_default
if /i "%opt%"=="H" goto help
if /i "%opt%"=="X" goto exit

echo Invalid option. Press any key.
pause >nul
goto menu

:: -------- Setter routines --------
:set_list
echo.
set /p "LIST_FILE=Enter list file path (or leave empty): "
goto menu
:set_range
echo.
set /p "RANGE_LIST=Enter range(s) (e.g., 192.168.1.1-192.168.1.10): "
goto menu
:set_port
echo.
set /p "PORT_LIST=Enter port(s) separated by space: "
goto menu
:set_threads
echo.
set /p "THREADS=Threads (default 50): "
if "%THREADS%"=="" set "THREADS=50"
goto menu
:set_timeout
echo.
set /p "TIMEOUT=Timeout seconds (default 60): "
if "%TIMEOUT%"=="" set "TIMEOUT=60"
goto menu
:set_tcp_mult
echo.
set /p "TCP_MULT=TCP multiplier (0.1-1.0, default 0.6): "
if "%TCP_MULT%"=="" set "TCP_MULT=0.6"
goto menu
:set_auth
echo.
set /p "AUTH=Auth (user:pass) or empty: "
goto menu
:set_ssh
echo.
set /p "SSH_HOST=SSH host [github.com]: "
if "%SSH_HOST%"=="" set "SSH_HOST=github.com"
set /p "SSH_PORT=SSH port [22]: "
if "%SSH_PORT%"=="" set "SSH_PORT=22"
goto menu
:set_alive
echo.
set /p "ALIVE_FILE=Alive output file [alive_proxies.txt]: "
if "%ALIVE_FILE%"=="" set "ALIVE_FILE=alive_proxies.txt"
goto menu
:set_urls
echo.
set /p "URLS_FILE=URLs output file [proxy_urls.txt]: "
if "%URLS_FILE%"=="" set "URLS_FILE=proxy_urls.txt"
goto menu
:set_checkpoint
echo.
set /p "CHECKPOINT=Checkpoint file [scan_progress.json]: "
if "%CHECKPOINT%"=="" set "CHECKPOINT=scan_progress.json"
goto menu
:set_scope
echo.
set /p "SCOPE=Scope CIDRs (space separated): "
goto menu
:set_allowall
if "%ALLOW_ALL%"=="--allow-all" (set "ALLOW_ALL=") else set "ALLOW_ALL=--allow-all"
goto menu
:set_targets
echo.
set /p "TARGETS_CFG=Targets config JSON file (or empty): "
goto menu
:set_fallback
echo.
set /p "FALLBACK_IPS=Fallback IPs JSON file [fallback_ips.json]: "
if "%FALLBACK_IPS%"=="" set "FALLBACK_IPS=fallback_ips.json"
goto menu
:set_nogeo
if "%NO_GEO%"=="--no-geo" (set "NO_GEO=") else set "NO_GEO=--no-geo"
goto menu
:set_nodiv
if "%NO_DIV%"=="--no-diversity" (set "NO_DIV=") else set "NO_DIV=--no-diversity"
goto menu
:set_verbose
if "%VERBOSE%"=="--verbose" (set "VERBOSE=") else set "VERBOSE=--verbose"
goto menu
:set_maxalive
echo.
set /p "MAX_ALIVE=Stop after N alive (0=unlimited): "
if "%MAX_ALIVE%"=="" set "MAX_ALIVE=0"
goto menu
:set_clean
if "%CLEAN%"=="--clean" (set "CLEAN=") else set "CLEAN=--clean"
goto menu
:set_retest
if "%RETEST%"=="--retest" (set "RETEST=") else set "RETEST=--retest"
goto menu
:set_refresh
if "%REFRESH%"=="--refresh-ips" (set "REFRESH=") else set "REFRESH=--refresh-ips"
goto menu

:: -------- Profile definitions --------
:quick
set "THREADS=20"
set "TIMEOUT=30"
set "NO_GEO=--no-geo"
set "NO_DIV=--no-diversity"
set "VERBOSE="
set "MAX_ALIVE=0"
goto check_and_run

:deep
set "THREADS=50"
set "TIMEOUT=90"
set "NO_GEO="
set "NO_DIV="
set "VERBOSE=--verbose"
set "MAX_ALIVE=0"
goto check_and_run

:full
set "THREADS=50"
set "TIMEOUT=120"
set "NO_GEO="
set "NO_DIV="
set "VERBOSE=--verbose"
set "MAX_ALIVE=0"
goto check_and_run

:custom
goto check_and_run

:check_and_run
:: Ensure we have either --list or --range (unless --refresh-ips is set)
if "%REFRESH%"=="--refresh-ips" goto run_scan
if "%LIST_FILE%"=="" if "%RANGE_LIST%"=="" (
    echo.
    echo [ERROR] No list file or range specified.
    echo Please set [1] List file or [2] Range before scanning.
    echo Or use [22] Refresh fallback IPs alone.
    pause
    goto menu
)
:: If list file is set but doesn't exist, ask again
if not "%LIST_FILE%"=="" if not exist "%LIST_FILE%" (
    echo.
    echo [ERROR] List file not found: %LIST_FILE%
    set "LIST_FILE="
    echo Please set a valid list file using option [1].
    pause
    goto menu
)
goto run_scan

:run_scan
:: Build command line
set "CMD=python "%SCRIPT%""

if not "%LIST_FILE%"=="" set "CMD=!CMD! --list "%LIST_FILE%""
if not "%RANGE_LIST%"=="" set "CMD=!CMD! --range %RANGE_LIST%"
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
if not "%ALLOW_ALL%"=="" set "CMD=!CMD! --allow-all"
if not "%TARGETS_CFG%"=="" set "CMD=!CMD! --targets-config "%TARGETS_CFG%""
if not "%FALLBACK_IPS%"=="" set "CMD=!CMD! --fallback-ips "%FALLBACK_IPS%""
if not "%NO_GEO%"=="" set "CMD=!CMD! --no-geo"
if not "%NO_DIV%"=="" set "CMD=!CMD! --no-diversity"
if not "%VERBOSE%"=="" set "CMD=!CMD! --verbose"
if %MAX_ALIVE% gtr 0 set "CMD=!CMD! --max-alive %MAX_ALIVE%"
if not "%CLEAN%"=="" set "CMD=!CMD! --clean"
if not "%RETEST%"=="" set "CMD=!CMD! --retest"
if not "%REFRESH%"=="" set "CMD=!CMD! --refresh-ips"

echo.
echo ===============================================================================
echo  RUNNING:
echo  !CMD!
echo ===============================================================================
echo.
echo [TIP] Press P to pause, R to resume during scan.
echo.
pause
call !CMD!
echo.
echo ===============================================================================
echo  Scan finished. Press any key to return to menu.
pause >nul
goto menu

:: -------- Save/Load/Help --------
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
echo Settings saved.
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
echo ================================= HELP =================================
echo.
echo PSI-TRACKER V1.0 "AEGIS PERFECTA" - FULL ARGUMENT REFERENCE
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
echo   Basic scan: set list file, then press C (Custom)
echo   CIDR scan : set range and ports, then press C
echo   Fast scan : press Q (Quick)
echo.
echo NOTES:
echo   - All tests go through the proxy itself. No direct internet required.
echo   - Press P and R inside the scan window to pause/resume.
echo   - Output files: alive_proxies.txt (detailed), proxy_urls.txt (ready to use)
echo.
pause
goto menu

:exit
exit /b 0
