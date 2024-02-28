``` mermaid
---
title: ESC8 - HTTP/S Enrollment Endpoints
---
flowchart LR
    HTTP/S(HTTP or HTTPS?) -- HTTP --> Critical
    HTTP/S(HTTP or HTTPS?) -- HTTPS --> Medium["Possible: No Finding, Medium\nCurrent: Medium*"]
```
```
* With current collection methods, we cannot determine true severity of this configuration.
  - If NTLM authentication is completely disabled (available at host level or IIS level), this is not a finding.
  - If EPA is enabled on IIS, the severity is Info.
  - Otherwise, this is a Medium severity issue.
```