$deploymentType = $args[0]
$username = $args[1]
$password = $args[2]
$option1 = $args[3]
$option2 = $args[4]
$option3 = $args[5]
$securePassword =  ConvertTo-SecureString $password -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($username, $securePassword)

if($deploymentType -eq "Resource"){
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    $domainFQDN = $domain.dnsroot
    $domusername = "$($domainFQDN)\$($username)"
    New-ADOrganizationalUnit Servers -Path $domain.DistinguishedName
    $ServerOU = "ou=Servers,$($domain.DistinguishedName)"
    New-ADOrganizationalUnit PKI -Path $ServerOU
    New-ADOrganizationalUnit ADFS -Path $ServerOU
    New-ADOrganizationalUnit APP -Path $ServerOU
    $PKIOU = "ou=PKI,$($ServerOU)"
    $ADFSOU = "ou=ADFS,$($ServerOU)"
    $APPOU = "ou=APP,$($ServerOU)"
    $scriptblockcontent = {
        Param ($Arg1,$Arg2,$Arg3,$Arg4,$Arg5)
        Add-Computer -ComputerName $Arg4 -DomainName $Arg1 -Credential (New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ($Arg2), (ConvertTo-SecureString $Arg3 -asplaintext -force)) -OUPath $Arg5 -Restart -Passthru -Verbose
    }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option1 -Force
    Invoke-Command -ComputerName $option1 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option1,$PKIOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option1
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option2 -Force
    Invoke-Command -ComputerName $option2 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option2,$ADFSOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option2
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option3 -Force
    Invoke-Command -ComputerName $option3 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option3,$APPOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option3
}
if($deploymentType -eq "Identity"){
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    $domainFQDN = $domain.dnsroot
    $domusername = "$($domainFQDN)\$($username)"
    New-ADOrganizationalUnit Servers -Path $domain.DistinguishedName
    New-ADOrganizationalUnit Clients -Path $domain.DistinguishedName
    $ServerOU = "ou=Servers,$($domain.DistinguishedName)"
    New-ADOrganizationalUnit PKI -Path $ServerOU
    New-ADOrganizationalUnit ADFS -Path $ServerOU
    $PKIOU = "ou=PKI,$($ServerOU)"
    $ADFSOU = "ou=ADFS,$($ServerOU)"
    $scriptblockcontent = {
        Param ($Arg1,$Arg2,$Arg3,$Arg4,$Arg5)
        Add-Computer -ComputerName $Arg4 -DomainName $Arg1 -Credential (New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ($Arg2), (ConvertTo-SecureString $Arg3 -asplaintext -force)) -OUPath $Arg5 -Restart -Passthru -Verbose
    }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option1 -Force
    Invoke-Command -ComputerName $option1 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option1,$PKIOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option1
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $option2 -Force
    Invoke-Command -ComputerName $option2 -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$option2,$ADFSOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $option2
}
if($deploymentType -eq "Workstation"){
    [array]$splitDom = $option1.split(".")
    $domusername = "$($splitDom[0])\$($username)"
    $ClientOU = "ou=Clients,dc=$($splitDom[0]),dc=$($splitDom[1])"
    $joincreds = New-Object System.Management.Automation.PSCredential($domusername, $securePassword)
    Add-Computer -ComputerName localhost -DomainName $option1 -Credential $joincreds -OUPath $ClientOU -Restart 
}
if($deploymentType -eq "PKI"){
    Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
}
if($deploymentType -eq "ADFS"){
    Install-windowsfeature adfs-federation –IncludeManagementTools
}
if($deploymentType -eq "APP"){
    Install-WindowsFeature Web-Server,Web-Asp-Net,Windows-Identity-Foundation -IncludeManagementTools
}
