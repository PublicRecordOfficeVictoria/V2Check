@echo off
set code="G:PROV\TECHNOLOGY MANAGEMENT\Application Development\VERS"
set versclasspath=%code%"
java -Xmx200m -classpath %versclasspath% VEOCheckII.VEOCheck %*