@echo off
cd /d "%~dp0"
echo Installing dependencies (first time only)...
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo Done. You can now double-click run.bat
pause
