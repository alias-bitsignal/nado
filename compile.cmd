python -m nuitka nado.py --standalone --windows-icon-from-ico=graphics\icon.ico
xcopy /e /i /y templates nado.dist\templates
xcopy /e /i /y static nado.dist\static
xcopy /e /i /y graphics nado.dist\graphics
"C:\Program Files (x86)\Inno Setup 6\iscc" /q "setup.iss"
pause
