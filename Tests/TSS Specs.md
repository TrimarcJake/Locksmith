# Tactical Speed Square: *the UnLocksmith*

## Auditing
Check if Audit level is set:
  - No: leave it
  - Yes: Set to 0

## ESC1
Find:
  - Name: ESC1
  - Config: Typical ESC1
  - Principal: ESC1 (user)

Find:
  - Name: ESC1and2
  - Config: "Any purpose" EKU
  - Principal: Domain Users

Do Not Find:
  - Name: ESC1Filtered
  - Config: Typical ESC1
  - Principal: Domain Admins

## ESC2
Find:
  - Name: ESC2
  - Config: Typical ESC2
  - Principal: ESC2 (user)

Find:
  - Name: ESC1and2
  - Config: "Any purpose" EKU
  - Principal: Domain Users

Do Not Find:
  - Name: ESC2Filtered
  - Config: Typical ESC2
  - Principal: Cert Publishers

## ESC3 - Not Complete
Find:
  - Name: ESC3Condition1

Find:
  - Name: ESC3Condition2

## ESC4
Find:
  - Name: ESC4GenericAll
  - Config: GenericAll
  - Principal: ESC4GenericAll

Find:
  - Name: ESC4WriteProperty
  - Config: WriteProperty on All Objects
  - Principal: ESC4WriteProperty

Find:
  - Name: ESC4WriteOwner
  - Config: WriteOwner
  - Principal: ESC4WriteOwner

Do Not Find:
  - Name: ESC4FilteredEnroll
  - Config WriteProperty, ExtendedRight on Enroll
  - Principal: Domain Users

Do Not Find:
  - Name: ESC4FilteredAutoEnroll
  - Config: WriteProperty, ExtendedRight on AutoEnroll
  - Principal: Domain Users

Do Not Find:
  - Name: ESC4FilteredSafeUsers
  - Config: GenericAll
  - Principal: Enteprise Admins

## ESC5
Find:
  - Name: ESC5GenericAll
  - Config: GenericAll
  - Principal: ESC5GenericAll

Find:
  - Name: ESC5WriteProperty
  - Config: WriteProperty on All Objects
  - Principal: ESC5WriteProperty

Find:
  - Name: ESC5WriteOwner
  - Config: WriteOwner
  - Principal: ESC4WriteOwner

Do Not Find:
  - Name: ESC5FilteredEnroll
  - Config WriteProperty, ExtendedRight on Enroll
  - Principal: Domain Users

Do Not Find:
  - Name: ESC5FilteredAutoEnroll
  - Config: WriteProperty, ExtendedRight on AutoEnroll
  - Principal: Domain Users

Do Not Find:
  - Name: ESC5FilteredSafeUsers
  - Config: GenericAll
  - Principal: Administrators

## ESC6
Check if dangerous flag exists:
  - Yes: leave it
  - No: set it

## ESC8 - Not Complete
Find:
  - HTTP Enrollment Endpoint

Find:
  - HTTPS Enrollment Endpoint
