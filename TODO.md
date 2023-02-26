## Short Term
- [ ] Add individual CA Hosts to $SafeUsers
- [ ] Rename Modes to something that makes sense
- [ ] Multi-Forest support
- [ ] Improved Output: Email, PS Object
- [ ] Check for Elevation before Fixing
- [ ] Check for installed Modules on Win 10/11

## Medium Term
- [ ] ESC7 and ESC8 coverage
- [ ] Text-Based User Interface
- [ ] Check for Auditing GPOS, Warn if none found
- [ ] ACL and Owner remediation snippets
- [ ] Improved Error Handling
- [ ] Include Reference Material

## Long Term
- [ ] Multi-Forest support
- [ ] Improved Output: Email, PS Object
- [ ] Convert from PS Modules/cmdlets to ADSI calls
- [ ] Unit testing (for [Jared](https://github.com/trimarcjared))

## Recently Completed
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
