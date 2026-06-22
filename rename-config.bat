@echo off
echo Renaming config.txt to config.js...
if exist config.js del config.js
if exist config.txt rename config.txt config.js
echo Done.
pause
