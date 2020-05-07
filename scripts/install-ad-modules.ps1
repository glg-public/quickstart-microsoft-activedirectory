[CmdletBinding()]
param()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

"Setting up Powershell Gallery to Install DSC Modules"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

"Installing the needed Powershell DSC modules"
Install-Module NetworkingDsc
Install-Module -Name "xActiveDirectory"
Install-Module ComputerManagementDsc
Install-Module -Name "xDnsServer"
Install-Module -Name "ActiveDirectoryCSDsc"

"Disabling Windows Firewall"
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

"Creating Directory for DSC Public Cert"
$CERTDIR = 'C:\AWSQuickstart\publickeys'
if(!(Test-Path -Path $CERTDIR )){
    New-Item -ItemType directory -Path $CERTDIR
}

"Setting up DSC Certificate to Encrypt Credentials in MOF File"
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'AWSQSDscEncryptCert' -HashAlgorithm SHA256
# Exporting the public key certificate
$cert | Export-Certificate -FilePath "$CERTDIR\AWSQSDscPublicKey.cer" -Force