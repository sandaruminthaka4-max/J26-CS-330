@echo off
title IoMT IDS MITM Detection System - Localhost Server
echo ===============================================================================
echo   IoMT Protocol Anomaly Detection & MITM Threat Alert Dashboard
echo   Starting Localhost Server at: http://localhost:5000
echo ===============================================================================
echo.
cd /d "%~dp0"

echo Opening Dashboard in your default browser...
start "" http://localhost:5000

echo Starting Flask Backend Server (Port 5000)...
echo Press Ctrl+C in this window anytime to stop the server.
echo.
python api/app.py
pause
