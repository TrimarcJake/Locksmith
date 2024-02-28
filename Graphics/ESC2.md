```mermaid
---
title: ESC2 - Sub CA
---
flowchart LR
    PrincipalType -->|User| UserType["User Type"];
            UserType -- ADA --> ADAUPriority(Info);
            UserType -- BO/PO/SO --> BIAUPriority(Low);
            UserType -- AO --> AOUPriority(Medium);
            UserType -- PKI --> PKIAUPriority(Info);
            UserType -- User --> UserPriority(Medium);
    PrincipalType -->|Group| GroupType("Group Type");
            GroupType -- AD Admins --> ADASize(ADA Group Size);
                ADASize -- Empty/Small --> ADAEGPriority(Info);
                ADASize -- Medium/Large --> ADAMGPriority(Info);
            GroupType -- Builtin Admin --> BIASize(BIA Group Size);
                BIASize -- Empty/Small --> BIAEGPriority(Info);
                BIASize -- Medium/Large --> BIAMGPriority(Low);
            GroupType -- PKI Admin --> PKIASize(PKI Group Size);
                PKIASize -- Empty/Small --> PKIAEGPriority(Info);
                PKIASize -- Medium/Large --> PKIAMGPriority(Low);
            GroupType -- Regular Users --> UsersSize(User Group Size);
                UsersSize -- Empty/Small --> UsersEGPriority(Medium);
                UsersSize -- Medium/Large --> UsersMGPriority(High);
    PrincipalType -->|gMSA| gMSAType(gMSA Type);
            gMSAType -- Any --> gMSAPriority(Info);
```