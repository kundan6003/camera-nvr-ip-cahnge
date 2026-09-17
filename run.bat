@echo off
cd /d "%~dp0"
echo Starting Bulk Device Config Tool...
echo Keep this window open while using the tool.
echo Open http://localhost:5000 in your browser.
echo.
python bulk_device_config_web.py
if errorlevel 1 (
  echo.
  echo Something went wrong - see the error above.
  pause
)
