$deploymentType = $args[0]
$username = $args[1]
$password = $args[2]
$CAIP = $args[3]
$ADFSIP = $args[4]
$APPorWKSIP = $args[5]
$securePassword =  ConvertTo-SecureString $password -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($username, $securePassword)


Import-Module ActiveDirectory
if($deploymentType -eq "Resource"){
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
        Add-Computer -ComputerName $Arg4 -DomainName $Arg1 -Credential (New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ($Arg1+"\"+$Arg2), (ConvertTo-SecureString $Arg3 -asplaintext -force)) -OUPath $Arg5 -Restart -Passthru -Verbose
    }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $CAIP -Force
    Invoke-Command -ComputerName $CAIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$CAIP,$PKIOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $CAIP
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ADFSIP -Force
    Invoke-Command -ComputerName $ADFSIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$ADFSIP,$ADFSOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $ADFSIP
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $APPorWKSIP -Force
    Invoke-Command -ComputerName $APPorWKSIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$APPorWKSIP,$APPOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $APPorWKSIP
}
if($deploymentType -eq "Identity"){
    $domain = Get-ADDomain
    $domainFQDN = $domain.dnsroot
    $domusername = "$($domainFQDN)\$($username)"
    New-ADOrganizationalUnit Servers -Path $domain.DistinguishedName
    New-ADOrganizationalUnit Clients -Path $domain.DistinguishedName
    $ServerOU = "ou=Servers,$($domain.DistinguishedName)"
    $ClientOU = "ou=Clients,$($domain.DistinguishedName)"
    New-ADOrganizationalUnit PKI -Path $ServerOU
    New-ADOrganizationalUnit ADFS -Path $ServerOU
    $PKIOU = "ou=PKI,$($ServerOU)"
    $ADFSOU = "ou=ADFS,$($ServerOU)"
    $scriptblockcontent = {
        Param ($Arg1,$Arg2,$Arg3,$Arg4,$Arg5)
        Add-Computer -ComputerName $Arg4 -DomainName $Arg1 -Credential (New-Object -Typename System.Management.Automation.PSCredential -Argumentlist ($Arg1+"\"+$Arg2), (ConvertTo-SecureString $Arg3 -asplaintext -force)) -OUPath $Arg5 -Restart -Passthru -Verbose
    }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $CAIP -Force
    Invoke-Command -ComputerName $CAIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$CAIP,$PKIOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $CAIP
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ADFSIP -Force
    Invoke-Command -ComputerName $ADFSIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$ADFSIP,$ADFSOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $ADFSIP
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $APPorWKSIP -Force
    Invoke-Command -ComputerName $APPorWKSIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$APPorWKSIP,$ClientOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $APPorWKSIP
}

