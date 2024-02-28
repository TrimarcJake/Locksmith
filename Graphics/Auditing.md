``` mermaid
---
title: Auditing
---
flowchart LR
    FullyEnabled[Fully Enabled] -- Yes --> NoFinding[No Finding]
    FullyEnabled -- No --> Info
```
Note: This check will be improved as we identify the auditing options that are important.