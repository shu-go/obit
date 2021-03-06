set NAME=obit

rem goxz -d dist -os windows -arch amd64,386 -build-ldflags "-s -w"

set GOOS=windows
set GOARCH=386
set ZIPNAME=%NAME%_%GOOS%_%GOARCH%.zip 
go build -ldflags "-s -w" %*
if errorlevel 1 pause
del %ZIPNAME% 2>nul
zip %ZIPNAME% *.exe README.txt LICENSE.txt

set GOOS=windows
set GOARCH=amd64
set ZIPNAME=%NAME%_%GOOS%_%GOARCH%.zip 
go build -ldflags "-s -w" %*
del %ZIPNAME% 2>nul
zip %ZIPNAME% *.exe README.txt LICENSE.txt
