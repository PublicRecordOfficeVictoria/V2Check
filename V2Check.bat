@echo off
if exist "J:/PROV/TECHNOLOGY MANAGEMENT/Application Development/VERS/VERSCode" (
	set code="J:/PROV/TECHNOLOGY MANAGEMENT/Application Development/VERS/VERSCode"
) else (
	set code="C:/Users/Andrew/Documents/Work/VERSCode"
)
java -classpath %code%/V2Check/dist/* VEOCheck.VEOCheck -values -signatures -f %code%/VERSCommon/VERSSupportFiles/validLTSF.txt -dtd %code%/VERSCommon/VERSSupportFiles/vers2.dtd %*
