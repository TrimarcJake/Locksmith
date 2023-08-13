# Tactical Speed Square: *the UnLocksmith*

## Auditing
Check if Audit level is set:
  - No: leave it
  - Yes: Set to 0

## ESC1
Find:
  - Name: ESC1
  - Config: Typical ESC1
  - Principal: Authenticated Users

  - Name: ESC1and2
  - Config: "Any purpose" EKU
  - Principal: Authenticated Users

Do Not Find:
  - Name: ESC1Filtered
  - Config: Typical ESC1
  - Principal: Administrators

## ESC2
Find:
  - Name: ESC2
  - Config: Typical ESC2
  - Principal: Authenticated Users

  - Name: ESC1and2
  - Config: "Any purpose" EKU
  - Principal: Authenticated Users

Do Not Find:
  - Name: ESC2Filtered
  - Config: Typical ESC2
  - Principal: Administrators

## ESC3 - Not Complete
Find:
  - Name: ESC3Condition1

Find:
  - Name: ESC3Condition2

## ESC4
Find:
  - Name: ESC4GenericAll
  - Config: GenericAll
  - Principal: Authenticated Users

  - Name: ESC4UnsafeOwner
  - Config: UnsafeOwner
  - Principal: Authenticated Users

  - Name: ESC4WriteProperty
  - Config: WriteProperty on All Objects
  - Principal: Authenticated Users

  - Name: ESC4WriteOwner
  - Config: WriteOwner
  - Principal: Authenticated Users

Do Not Find:
  - Name: ESC4FilteredEnroll
  - Config WriteProperty, ExtendedRight on Enroll
  - Principal: Domain Users

  - Name: ESC4FilteredAutoEnroll
  - Config: WriteProperty, ExtendedRight on AutoEnroll
  - Principal: Domain Users

  - Name: ESC4FilteredOwner
  - Config: Owner
  - Principal: Administrators

  - Name: ESC4FilteredSafeUsers
  - Config: GenericAll
  - Principal: Administrators

## ESC5
Find:
  - Name: ESC5GenericAll
  - Config: GenericAll
  - Principal: Authenticated Users

  - Name: ESC5UnsafeOwner
  - Config: UnsafeOwner
  - Principal: Authenticated Users

  - Name: ESC5WriteProperty
  - Config: WriteProperty on All Objects
  - Principal: Authenticated Users

  - Name: ESC5WriteOwner
  - Config: WriteOwner
  - Principal: Authenticated Users

Do Not Find:
  - Name: ESC5FilteredEnroll
  - Config WriteProperty, ExtendedRight on Enroll
  - Principal: Authenticated Users

  - Name: ESC5FilteredAutoEnroll
  - Config: WriteProperty, ExtendedRight on AutoEnroll
  - Principal: Authenticated Users

  - Name: ESC5FilteredOwner
  - Config: Owner
  - Principal: Administrators

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
