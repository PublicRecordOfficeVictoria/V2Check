@echo off
rem set code="C:\Users\Andrew\Documents\Work\VERS-2015\VPA"
set code="J:\PROV\TECHNOLOGY MANAGEMENT\Application Development\VERS\VERS-1999\V2Check"
set versclasspath=%code%/dist/*
java -classpath %versclasspath% VEOCheck.VEOCheck -all %*
