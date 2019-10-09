$deploymentType = $args[0]
$username = $args[1]
$password = $args[2]
$CAIP = $args[3]
$ADFSIP = $args[4]
$APPIP = $args[5]
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
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $CAIP -Force
    Invoke-Command -ComputerName $CAIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$CAIP,$PKIOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $CAIP
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ADFSIP -Force
    Invoke-Command -ComputerName $ADFSIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$ADFSIP,$ADFSOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $ADFSIP
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $APPIP -Force
    Invoke-Command -ComputerName $APPIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$APPIP,$APPOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $APPIP
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
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $CAIP -Force
    Invoke-Command -ComputerName $CAIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$CAIP,$PKIOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $CAIP
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ADFSIP -Force
    Invoke-Command -ComputerName $ADFSIP -Credential $creds -ScriptBlock $scriptblockcontent -ArgumentList ($domainFQDN,$domusername,$password,$ADFSIP,$ADFSOU)
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Include $ADFSIP
}
if($deploymentType -eq "Workstation"){
    $domusername = "$($username)@$($CAIP)"
    [array]$splitDom = $CAIP.split(".")
    $ClientOU = "ou=Clients,dc=$($splitDom[1]),dc=$($splitDom[0])"
    $wkscreds = New-Object System.Management.Automation.PSCredential($domusername, $securePassword)
    Add-Computer -ComputerName localhost -DomainName $CAIP -Credential $wkscreds -OUPath $ClientOU -Restart 
}
