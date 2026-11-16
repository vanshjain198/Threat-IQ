@echo off
:: start.bat — Start all Threat-IQ services on Windows

echo.
echo 🛡️  Threat-IQ Startup Script (Windows)
echo ======================================
echo.

:: Check if models exist
if not exist "ml-service\models\random_forest_model.pkl" (
    echo [!] Models not found. Running training first...
    cd ml-service
    python train.py
    cd ..
)

echo [1/3] Starting ML service (port 8000)...
start "Threat-IQ ML Service" cmd /k "cd ml-service && python -m uvicorn main:app --port 8000"
timeout /t 3 /nobreak > nul

echo [2/3] Starting Node.js backend (port 3001)...
start "Threat-IQ Backend" cmd /k "cd server && node index.js"
timeout /t 2 /nobreak > nul

echo [3/3] Starting React dashboard (port 5173)...
start "Threat-IQ Dashboard" cmd /k "cd client && npm run dev"

echo.
echo All services starting in separate windows!
echo.
echo   Dashboard  : http://localhost:5173
echo   Backend    : http://localhost:3001
echo   ML Service : http://localhost:8000
echo.
echo Tip: Open http://localhost:5173 and click "Start Demo" to test live attacks!
echo.
pause
