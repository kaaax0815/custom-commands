@echo off
if "%~1"=="" goto error
git init
git remote add origin %1
goto end

:error
echo No Repo selected

:end