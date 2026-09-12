@echo off
rem AEGIS one-click stop (ASCII only)
echo stopping AEGIS processes ...

wmic process where "CommandLine like '%%aegis-console-1.0.0.jar%%'" call terminate >nul 2>&1
wmic process where "CommandLine like '%%vuln-target-1.0.0.jar%%'" call terminate >nul 2>&1
wmic process where "CommandLine like '%%aegis-gateway-1.0.0.jar%%'" call terminate >nul 2>&1
wmic process where "Name='node.exe' and CommandLine like '%%aegis-web%%'" call terminate >nul 2>&1

taskkill /fi "WindowTitle eq AEGIS-1-console-8080*" /f >nul 2>&1
taskkill /fi "WindowTitle eq AEGIS-2-target-8090*" /f >nul 2>&1
taskkill /fi "WindowTitle eq AEGIS-3-gateway-8000*" /f >nul 2>&1
taskkill /fi "WindowTitle eq AEGIS-4-web-5173*" /f >nul 2>&1

echo done.
ping -n 4 127.0.0.1 >nul
exit /b 0
