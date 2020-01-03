@echo off
set code="C:\Users\Andrew\Documents\Work\VERSCode\V2Check"
rem set code="J:\PROV\TECHNOLOGY MANAGEMENT\Application Development\VERS\VERSCode\V2Check"
set versclasspath=%code%/dist/*
java -classpath %versclasspath% VEOCheck.VEOCheck -all %*
