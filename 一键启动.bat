@echo off
rem AEGIS one-click launcher (ASCII only)
setlocal
cd /d "%~dp0"

set "JAVA=C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot\bin\java.exe"
if not exist "%JAVA%" (
  echo [ERROR] JDK17 not found
  pause
  exit /b 1
)

if not exist "aegis-console\target\aegis-console-1.0.0.jar" echo [ERROR] missing console jar & pause & exit /b 1
if not exist "aegis-gateway\target\aegis-gateway-1.0.0.jar" echo [ERROR] missing gateway jar & pause & exit /b 1
if not exist "vuln-target\target\vuln-target-1.0.0.jar" echo [ERROR] missing target jar & pause & exit /b 1
if not exist "aegis-agent\target\aegis-agent.jar" echo [ERROR] missing agent jar & pause & exit /b 1

echo [1/4] console :8080
start "AEGIS-1-console-8080" "%JAVA%" -Dfile.encoding=UTF-8 -jar aegis-console\target\aegis-console-1.0.0.jar
ping -n 9 127.0.0.1 >nul

echo [2/4] target + RASP :8090 (BLOCK)
start "AEGIS-2-target-8090" "%JAVA%" -Dfile.encoding=UTF-8 -javaagent:aegis-agent\target\aegis-agent.jar=console=http://localhost:8080,mode=BLOCK -jar vuln-target\target\vuln-target-1.0.0.jar
ping -n 9 127.0.0.1 >nul

echo [3/4] gateway :8000
start "AEGIS-3-gateway-8000" "%JAVA%" -Dfile.encoding=UTF-8 -jar aegis-gateway\target\aegis-gateway-1.0.0.jar
ping -n 7 127.0.0.1 >nul

echo [4/4] web :5173
start "AEGIS-4-web-5173" cmd /k "cd /d "%~dp0aegis-web" && npm run dev"
ping -n 16 127.0.0.1 >nul

echo =====================================================
echo  AEGIS is UP
echo    Dashboard       : http://localhost:5173
echo    Protected entry : http://localhost:8000/api/notes/list?page=1
echo    Direct target   : http://localhost:8090/api/notes/list?page=1
echo  NOTE: 8000/8090 are API only - no homepage there.
echo        Use the UI at 5173. Login: admin / admin123
echo =====================================================
start http://localhost:5173
ping -n 6 127.0.0.1 >nul
exit /b 0
