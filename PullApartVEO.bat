echo n
set code="G:PROV\TECHNOLOGY MANAGEMENT\Application Development\VERS"
set javaExec=%code%\j2sdk1.4.1_05\bin\java"
set xalanDir=%code%\xalan-j_2_6_0"
set versclasspath=%code%
java -Xmx200m -classpath %versclasspath% VEOCheckII.PullApartVEO %1 %2 %3