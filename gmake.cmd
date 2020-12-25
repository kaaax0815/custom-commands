@echo off
if "%~1"=="" goto error
IF NOT "%~2" == "" GOTO error2
SET paramter=%~1
git add .
git commit -a -m "%paramter%"
goto end

:error
echo No Commit message specified
goto end

:error2
echo Use Quotes

:end