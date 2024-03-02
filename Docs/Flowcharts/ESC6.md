``` mermaid
---
title: ESC6 - Dangerous Flag on CA
---
flowchart LR
    FlagSet["Flag Set"] -- Yes --> High
    FlagSet["Flag Set"] -- No --> NoFinding[No Finding]
```
```
* This check can be improved by checking Domain Controller registries. (Coming soon!)  
If StrongMapping is manually disabled on any DC, this becomes a Critical issue.
```
