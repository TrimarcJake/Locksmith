```
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'


########## Auditing Issues ##########


Technique Name         Issue
--------- ----         -----
DETECT    horse-DC1-CA Auditing is not fully enabled. Current value is 0



########## ESC1 - Misconfigured Certificate Template ##########

Technique Name            Issue
--------- ----            -----
ESC1      ESC1-Vulnerable HORSE\kari can enroll in this Client Authentication template using a SAN without Manager Approval



########## ESC2 - Misconfigured Certificate Template ##########

Technique Name            Issue
--------- ----            -----
ESC2      ESC2-Vulnerable NT AUTHORITY\Authenticated Users can request a SubCA certificate without Manager Approval



########## ESC4 - Vulnerable Certifcate Template Access Control ##########

Technique Name                    Issue
--------- ----                    -----
ESC4      User                    NT AUTHORITY\Authenticated Users has GenericAll rights on this template
ESC4      User                    HORSE\Domain Users has GenericAll rights on this template


########## ESC5 - Vulnerable PKI Object Access Control ##########

Technique Name         Issue
--------- ----         -----
ESC5      horse-DC1-CA HORSE\kari has CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete,
                       GenericRead, WriteDacl, WriteOwner rights on this object
ESC5      DC1          HORSE\kari has GenericAll rights on this object


########## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 ##########

Technique Name         Issue
--------- ----         -----
ESC6      horse-DC1-CA EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.


########## ESC8 - HTTP Enrollment Enabled ##########

Technique Name         Issue
--------- ----         -----
ESC8      horse-DC1-CA HTTP enrollment is enabled.