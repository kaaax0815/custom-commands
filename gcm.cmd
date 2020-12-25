@echo off
if "%~1"=="" goto error
echo git commit -a -m "%1 %2 %3 %4"
goto end

:error
echo No Commit message specified

:end