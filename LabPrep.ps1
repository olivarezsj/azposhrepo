$deploymentType = $args[0]
$username = $args[1]
$password = $args[2]
$option1 = $args[3]
$option2 = $args[4]
$option3 = $args[5]
if($username -ne $null){
$securePassword =  ConvertTo-SecureString $password -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($username, $securePassword)
}


if($deploymentType -eq "Lab"){
    #Creates OU structure
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    $domainFQDN = $domain.dnsroot
    $domusername = "$($domainFQDN)\$($username)"
    $scriptblockcontent = {
        Param ($Arg1,$Arg2,$Arg3,$Arg4,$Arg5)
        Add-Computer -ComputerName $Arg4 -DomainName $Arg1 -Credential (New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ($Arg2), (ConvertTo-SecureString $Arg3 -asplaintext -force)) -OUPath $Arg5 -Restart -Passthru -Verbose
    }
    try {
        New-ADOrganizationalUnit Clients -Path $domain.DistinguishedName
    }
    catch {
        Write-Output $_.Exception.Message
    }
    try {
        New-ADOrganizationalUnit Servers -Path $domain.DistinguishedName
    }
    catch {
        Write-Output $_.Exception.Message
    }
    $ServerOU = "ou=Servers,$($domain.DistinguishedName)"
    try {
        New-ADOrganizationalUnit PKI -Path $ServerOU
        $PKIOU = "ou=PKI,$($ServerOU)"
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option1 -Force
        Invoke-Command -ComputerName $option1 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option1,$PKIOU)
        Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option1
    }
    catch {
        Write-Output $_.Exception.Message
    }
    try {
        New-ADOrganizationalUnit APP -Path $ServerOU
        $APPOU = "ou=APP,$($ServerOU)"
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option2 -Force
        Invoke-Command -ComputerName $option2 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option2,$APPOU)
        Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option2
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option3 -Force
        Invoke-Command -ComputerName $option3 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option3,$APPOU)
        Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option3
    }
    catch {
        Write-Output $_.Exception.Message
    }

    $CAInstcreds = New-Object System.Management.Automation.PSCredential($domusername, $securePassword)
    $CAInstallscriptblockcontent = {
        Param ($Arg1,$Arg2,$Arg3)
        $CAName = "$Arg1-RootCA"
        $CAcred = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ($Arg2), (ConvertTo-SecureString $Arg3 -asplaintext -force)
        Import-module ADCSDeployment
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CACommonName $CAName -Credential $CAcred -CryptoProviderName "ECDSA_P256#Microsoft Software Key Storage Provider" -KeyLength 256 -HashAlgorithmName SHA256
        }
    Invoke-Command -ComputerName $option1 -Credential $CAInstcreds -ScriptBlock $CAInstallscriptblockcontent -ArgumentList ($deploymentType,$domusername,$password)
    
    #Create new Certificate Template
    $WebServerCT = Get-ADObject -Identity "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($domain.DistinguishedName)" -Properties *
    $CertTemplateAttributes = @{
        "flags"="131649";
        "revision"="100";
        "pKIDefaultKeySpec" = "1";
        "pKIMaxIssuingDepth"="0";
        "pKICriticalExtensions"="2.5.29.15";
        "pKIExtendedKeyUsage"="1.3.6.1.5.5.7.3.1"
        "pKIDefaultCSPs"=@("1,Microsoft RSA SChannel Cryptographic Provider","2,Microsoft DH SChannel Cryptographic Provider");
        "msPKI-RA-Signature"="0";
        "msPKI-Enrollment-Flag"="0";
        "msPKI-Private-Key-Flag"="101056768";
        "msPKI-Certificate-Name-Flag"="1";
        "msPKI-Minimal-Key-Size"="2048"
        "msPKI-Template-Schema-Version"="4";
        "msPKI-Template-Minor-Revision"="2";
        "msPKI-Cert-Template-OID"="1.3.6.1.4.1.311.21.8.15767579.15718837.13781421.6810505.13041814.86.16015666.16460173";
        "msPKI-Certificate-Application-Policy"="1.3.6.1.5.5.7.3.1";
        "pKIKeyUsage"=$WebServerCT.pKIKeyUsage;
        "pKIExpirationPeriod"=$WebServerCT.pKIExpirationPeriod;
        "pKIOverlapPeriod"=$WebServerCT.pKIOverlapPeriod
    }   
    New-ADObject -Name UpdatedWebServer -Type pKICertificateTemplate -DisplayName UpdatedWebServer -OtherAttributes $CertTemplateAttributes `
    -Path "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($domain.DistinguishedName)"

    #Modify permissions on new certificate template
    [System.GUID]$autoenrollGuid = (Get-ADObject -Identity "CN=Certificate-AutoEnrollment,CN=Extended-Rights,CN=Configuration,$($domain.DistinguishedName)" -Properties rightsGuid).rightsGuid
    [System.GUID]$enrollGuid = (Get-ADObject -Identity "CN=Certificate-Enrollment,CN=Extended-Rights,CN=Configuration,$($domain.DistinguishedName)" -Properties rightsGuid).rightsGuid
    $certificateTemplate = Get-ADObject -Identity "CN=UpdatedWebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=resource,DC=lab"
    $APP1_SID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADComputer $option2).SID
    $APP2_SID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADComputer $option3).SID
    $CertTempAcl = Get-ACL -Path ("AD:$($certificateTemplate.DistinguishedName)")
    $CertTempAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $APP1_SID,"ReadProperty, GenericExecute","Allow")) 
    $CertTempAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $APP1_SID,"ExtendedRight","Allow",$autoenrollGuid))   
    $CertTempAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $APP1_SID,"ExtendedRight","Allow",$enrollGuid)) 
    $CertTempAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $APP2_SID,"ReadProperty, GenericExecute","Allow")) 
    $CertTempAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $APP2_SID,"ExtendedRight","Allow",$autoenrollGuid))   
    $CertTempAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
    $APP2_SID,"ExtendedRight","Allow",$enrollGuid)) 
    Set-ACL -ACLObject $acl -Path ("AD:$($ct.DistinguishedName)")
}
if($deploymentType -eq "Workstation"){
    [array]$splitDom = $option1.split(".")
    $domusername = "$($splitDom[0])\$($username)"
    $ClientOU = "ou=Clients,dc=$($splitDom[0]),dc=$($splitDom[1])"
    $joincreds = New-Object System.Management.Automation.PSCredential($domusername, $securePassword)
    Add-Computer -ComputerName localhost -DomainName $option1 -Credential $joincreds -OUPath $ClientOU -Restart 
}
if($deploymentType -eq "PKI"){
    Import-module servermanager
    Install-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools
}
