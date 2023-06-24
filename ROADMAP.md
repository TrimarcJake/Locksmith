## Continuous
- Improved Error Handling

## Short Term
- [ ] Rename Modes to something that makes sense
- [ ] Improved Output: Email, PS Object
- [ ] Check for Elevation before Fixing
- [ ] ACL remediation snippets

## Medium Term
- [ ] ESC3 coverage
- [ ] ESC7 coverage
- [ ] Text-Based User Interface
- [ ] Check for Auditing GPOS, Warn if none found
- [ ] Include Reference Material

## Long Term
- [ ] Convert from PS Modules/cmdlets to ADSI calls
- [ ] ESC8 Remediation
- [ ] Unit testing (for [Jared](https://github.com/trimarcjared))
- [ ] ESC3 Remediation
- [ ] ESC7 Remediation
- [ ] Multi-Forest support

## Recently Completed
- [x] Add individual CA Hosts to $SafeUsers
- [x] Add sample output to README.md
- [x] ESC8 coverage
- [x] Modes 0 & 1: Headers for Console Output
- [x] Mode 4: Display snippet and get confirmation before running.
  - [x] Include details about how changes could affect environment. 
- [x] Add Domain Controllers group, ENTERPRISE DOMAIN CONTROLLERS group, to $SafeUsers
- [x] Add Forest name to "Cert Publishers" and "Administrator" definitions in $SafeOwners and $SafeUsers
- [x] Update README.md with Examples
- [x] Script to reset any fixed items
- [x] Testing of all modes
- [x] Backup before running Mode 4
- [x] Strict Mode support
- [x] RDP Restricted Admin support
- [x] Convert $SafeOwners and $SafeUsers to SIDs
- [x] Check for installed Modules on Win 10/11
- [x] Owner remediation snippets
