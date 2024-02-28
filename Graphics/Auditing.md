``` mermaid
---
title: Auditing
---
flowchart LR
    FullyEnabled[Fully Enabled] -- Yes --> NoFinding[No Finding]
    FullyEnabled -- No --> Info
```
Note: We don't actually perform this check at this time.