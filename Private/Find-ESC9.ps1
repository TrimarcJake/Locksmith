<#
    This is a working POC. I need to test both checks and possibly blend pieces of them.
    Then I need to fold this function into the Locksmith workflow.
#>

function Find-ESC9 {
<#
    .SYNOPSIS
        Checks for ESC9 (No Security Extension) Vulnerability

    .DESCRIPTION
        This function checks for certificate templates that contain the flag CT_CLAG_NO_SECURITY_EXTENSION (0x80000),
        which will likely make them vulnerable to ESC9. Another factor to check for ESC9 is the registry values on AD
        domain controllers that can help harden certificate based authentication for Kerberos and SChannel.

    .NOTES
        An ESC9 condition exists when:

        - the new msPKI-Enrollment-Flag value on a certificate contains the flag CT_FLAG_NO_SECURITY_EXTENSION (0x80000)
        - AND an insecure regstry value is set on domain controllers:

          - the StrongCertificateBindingEnforcement registry value for Kerberos is not set to 2 (the default is 1) on domain controllers
            at HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc
          - OR the CertificateMappingMethods registry value for SCHANNEL contains the UPN flag on domain controllers at
            HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel

        When the CT_FLAG_NO_SECURITY_EXTENSION (0x80000) flag is set on a certificate template, the new szOID_NTDS_CA_SECURITY_EXT
        security extension will not be embedded in issued certificates. This security extension was added by Microsoft's
        patch KB5014754 ("Certificate-based authentication changes on Windows domain controllers") on May 10, 2022.

        The patch applies to all servers that run Active Directory Certificate Services and Windows domain controllers that
        service certificate-based authentication.
        https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

        Based on research from
        https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7,
        https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16,
        and on a very long conversation with Bing Chat.

        Additional notes from Cortana -- Bing when I pressed her to  tell me whether both conditions were required for ESC9 or only one of them:
            A certificate template can still be vulnerable to ESC9 even if the msPKI-Enrollment-Flag does not include
            CT_FLAG_NO_SECURITY_EXTENSION. This is because the vulnerability primarily arises from the ability of a
            requester to specify the subjectAltName in a Certificate Signing Request (CSR). If a requester can specify
            the subjectAltName in a CSR, they can request a certificate as anyone, including a domain admin user.
            Therefore, if a certificate template allows requesters to specify a subjectAltName and
            StrongCertificateBindingEnforcement is not set to 2, it could potentially be vulnerable to ESC9. However,
            the presence of CT_FLAG_NO_SECURITY_EXTENSION in msPKI-Enrollment-Flag is a clear indicator of a template
            being vulnerable to ESC9.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $ADCSObjects
    )

    # Import the required module
    Import-Module ActiveDirectory

    # Get the configuration naming context
    $configNC = (Get-ADRootDSE).configurationNamingContext

    # Define the path to the Certificate Templates container
    $path = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    # Get all certificate templates
    $templates = Get-ADObject -Filter * -SearchBase $path -Properties msPKI-Enrollment-Flag, msPKI-Certificate-Name-Flag

    foreach ($template in $templates) {
        # Check if msPKI-Enrollment-Flag contains the CT_FLAG_NO_SECURITY_EXTENSION (0x80000) flag
        if ($template.'msPKI-Enrollment-Flag' -band 0x80000) {
            # Check if msPKI-Certificate-Name-Flag contains the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME (0x2) flag
            if ($template.'msPKI-Certificate-Name-Flag' -band 0x2) {
                # Output the template name
                Write-Output "Template Name: $($template.Name), Vulnerable to ESC9"
            }
        }
    }

    # AND / OR / ALSO

    Import-Module ActiveDirectory

    $templates = Get-ADObject -Filter {ObjectClass -eq "pKICertificateTemplate"} -Properties *
    foreach ($template in $templates) {
        $name = $template.Name

        $subjectNameFlag     = $template.'msPKI-Cert-Template-OID'
        $subjectType         = $template.'msPKI-Certificate-Application-Policy'
        $enrollmentFlag      = $template.'msPKI-Enrollment-Flag'
        $certificateNameFlag = $template.'msPKI-Certificate-Name-Flag'

        # Check if the template is vulnerable to ESC9
        if ($subjectNameFlag -eq "Supply in the request" -and
                ($subjectType -eq "User" -or $subjectType -eq "Computer") -and
                # 0x200 means a certificate needs to include a template name certificate extension
                # 0x220 instructs the client to perform autoenrollment for the specified template
                ($enrollmentFlag -eq 0x200 -or $enrollmentFlag -eq 0x220) -and
                # 0x2 instructs the client to supply subject information in the certificate request (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT).
                #   This means that any user who is allowed to enroll in a certificate with this setting can request a certificate as any
                #   user in the network, including a privileged user.
                # 0x3 instructs the client to supply both the subject and subject alternate name information in the certificate request
                ($certificateNameFlag -eq 0x2 -or $certificateNameFlag -eq 0x3)) {

            # Print the template name and the vulnerability
            Write-Output "$name is vulnerable to ESC9"
        }
        else {
            # Print the template name and the status
            Write-Output "$name is not vulnerable to ESC9"
        }
    }

}
