@echo off
title IoMT Reconnaissance IDS - Demo Launcher
echo =====================================================================
echo  Starting Lightweight IoMT Reconnaissance IDS & Mock SDN Controller
echo =====================================================================
echo.

echo [1/3] Starting Mock SDN Controller on port 8080...
start "Mock SDN Controller (Port 8080)" cmd /k "python -m uvicorn src.integration.mock_controller:mock_app --port 8080"

timeout /t 2 /nobreak > nul

echo [2/3] Starting Reconnaissance IDS API & Dashboard on port 8000...
start "Reconnaissance IDS API (Port 8000)" cmd /k "python -m uvicorn src.api.app:app --port 8000"

timeout /t 2 /nobreak > nul

echo [3/3] Opening Dashboard in browser...
start http://localhost:8000

echo.
echo =====================================================================
echo  Services started successfully!
echo  Dashboard: http://localhost:8000
echo  API Docs:  http://localhost:8000/docs
echo  SDN Mock:  http://localhost:8080/health
echo =====================================================================
pause
