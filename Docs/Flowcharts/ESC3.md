```mermaid
---
title: ESC3 Condition 1 - Enrollment Agent
---
flowchart LR
    PrincipalType -->|User| UserType["User Type"];
            UserType -- AD Admin --> ADAUPriority(Low);
            UserType -- Builtin/PKI Admin --> BIAUPriority(Medium);
            UserType -- User --> UserPriority(High);
    PrincipalType -->|Group| GroupType("Group Type");
            GroupType -- AD Admins --> ADASize(No Finding);
            GroupType -- Builtin/PKI Admins --> BIASize(Group Size);
                BIASize -- Empty/Small --> BIAEGPriority(No Info);
                BIASize -- Medium/Large --> BIAMGPriority(Low);
            GroupType -- Regular Users --> UsersSize(Group Size);
                UsersSize -- Empty/Small --> UsersEGPriority(Low);
                UsersSize -- Medium/Large --> UsersMGPriority(Medium);
    PrincipalType -->|gMSA| gMSAType(gMSA Type);
            gMSAType -- Any --> gMSAPriority(No Finding);
```
