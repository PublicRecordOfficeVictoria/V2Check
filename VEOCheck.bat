@echo off
set code=C:\Documents and Settings\Andrew Waugh\My Documents\Work\OldVEO\VEOCheckII
set versclasspath="%code%\build\classes"
java -Xmx200m -classpath %versclasspath% VEOCheck.VEOCheck -extract %*