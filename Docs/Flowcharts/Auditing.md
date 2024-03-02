``` mermaid
---
title: Auditing
---
flowchart LR
    FullyEnabled[Fully Enabled] -- Yes --> NoFinding[No Finding]
    FullyEnabled -- No --> Info
```