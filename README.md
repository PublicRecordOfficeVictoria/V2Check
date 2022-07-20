# V2Check

Copyright Public Records Office Victoria 2022

License CC BY 4.0

## What is VERS?

This package is part of the Victorian Electronic Records Strategy (VERS)
software release. For more information about VERS see
[here](https://prov.vic.gov.au/recordkeeping-government/vers).

## What is V2Check?

V2Check analyses a VERS Version 2 (VERS V2) VERS Encapsulated Objects (VEOs).

V2Check can
- test that the VEO is valid according to the V2 DTD
- test metadata constraints
- test that digital signatures validate
- test that each document has an encoding in a long term sustainable format
- unpack the encodings in the VEO

Version 2 VEOs are specified in PROS 99/007. This specification is now obsolete
and you should use VERS V3. The equivalent code can be found in the neoVEO
package.

## Using V2Check

V2Check is run from the command line. 'v2check -help' will print a precis of
the command line options. The package contains a BAT file and a manual.

To use this package you also need to download the VERSCommon package, and this
must be placed in the same directory as the V2Check package.

Structurally, the package is an Apache Netbeans project.