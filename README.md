# GetDBinfo
数据敏感信息获取

————————————

GetSQLiteInfo脚本：


@echo off

echo  aa

echo  [*] 一键获取SQLite数据库数据及敏感信息脚本。

echo  [*] 说明：

echo   	基于SQLite3模板写，仅支持sqlite数据库格式

echo   [*] useage:

echo   	

echo   	python3 GetSQLiteinfo.py --file  hqt.sqlite  # 指定文件

echo   	python3 GetSQLiteinfo.py --dir /path/to/directory   #指定目录，批量获取

echo.

call  cmd.exe

pause

