if "%vcinstalldir%"=="" call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsx86_amd64.bat"
cl.exe /nologo /O2 cc1352r1.c setupapi.lib winusb.lib
