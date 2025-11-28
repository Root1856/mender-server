@echo off
REM Run all POC scripts for Mender Server vulnerabilities
REM Windows batch file version

set BASE_URL=%1
if "%BASE_URL%"=="" set BASE_URL=https://staging.hosted.mender.io

echo ============================================================
echo Mender Server Security POC Test Suite
echo ============================================================
echo.
echo Target: %BASE_URL%
echo WARNING: These tests attempt to exploit vulnerabilities!
echo Only run on test/staging environments!
echo.
pause

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [-] python not found. Please install Python 3.
    exit /b 1
)

REM Install required packages
echo [*] Checking Python dependencies...
python -m pip install --quiet requests 2>nul
if errorlevel 1 (
    echo [-] Failed to install requests. Run: pip install requests
    exit /b 1
)

echo.
echo ============================================================
echo Running POC Tests
echo ============================================================
echo.

REM Test 1: RBAC Header Injection
echo [TEST 1/5] RBAC Scope Header Injection (CRITICAL)
echo ------------------------------------------------------------
python poc\vulnerability_1_rbac_header_injection.py %BASE_URL%
echo.

REM Test 2: JWT Forgery
echo [TEST 2/5] JWT Identity Extraction Without Verification (HIGH)
echo ------------------------------------------------------------
python poc\vulnerability_2_jwt_forgery.py %BASE_URL%
echo.

REM Test 3: RBAC Scope Validation
echo [TEST 3/5] Missing RBAC Scope Validation (HIGH)
echo ------------------------------------------------------------
echo [NOTE] This is tested as part of Test 1 (reporting API endpoints)
echo.

REM Test 4: Command Injection
echo [TEST 4/5] Command Injection in Workflow CLI (CRITICAL)
echo ------------------------------------------------------------
echo [!] WARNING: This test attempts to execute commands on the server!
set /p CONTINUE="Continue with command injection test? (y/N): "
if /i "%CONTINUE%"=="y" (
    python poc\vulnerability_4_command_injection.py %BASE_URL%
) else (
    echo [SKIPPED] Command injection test skipped by user
)
echo.

REM Test 5: Path Traversal
echo [TEST 5/5] Path Traversal in File Transfer (MEDIUM)
echo ------------------------------------------------------------
python poc\vulnerability_5_path_traversal.py %BASE_URL%
echo.

echo ============================================================
echo POC Test Suite Complete
echo ============================================================
echo.
echo Review the output above for vulnerability confirmations.
echo Check CRITICAL_VULNERABILITIES.md for detailed information.
pause

