[CmdletBinding()]
# Incoming Parameters for Script, Terraform/SSM Parameters being passed in
param(
    [Parameter(Mandatory=$true)]
    [string]$ThisDCNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$DomainDNSName,

    [Parameter(Mandatory=$true)]
    [string]$DNSServer,

    [Parameter(Mandatory=$true)]
    [string]$ADAdminSecParam,

    [Parameter(Mandatory=$true)]
    [string]$InstanceTimeZone
)

# Grabbing Mac Address for Primary Interface to Rename Interface
$MacAddress = (Get-NetAdapter).MacAddress
# Getting Secrets Information for Domain Administrator
$ADAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $ADAdminSecParam).SecretString
# Formatting AD Admin User to proper format for JoinDomain DSC Resources in this Script
$DomainAdmin = 'Domain\User' -replace 'Domain',$DomainNetBIOSName -replace 'User',$ADAdminPassword.UserName
# Creating Credential Object for Domain Admin User
$Credentials = (New-Object PSCredential($DomainAdmin,(ConvertTo-SecureString $ADAdminPassword.Password -AsPlainText -Force)))
# Getting the DSC Cert Encryption Thumbprint to Secure the MOF File
$DscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | where { $_.subject -eq "CN=AWSQSDscEncryptCert" }).Thumbprint

# Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName="*"
            CertificateFile = "C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer"
            Thumbprint = $DscCertThumbprint
            PSDscAllowDomainUser = $true
        },
        @{
            NodeName = 'localhost'
        }
    )
}

# PowerShell DSC Configuration Block for GLG Domain Controller
Configuration ConfigGlgDC {
    # Credential Objects being passed in
    param
    (
        [PSCredential] $Credentials
    )
    
    # Importing DSC Modules needed for Configuration
    Import-Module -Name PSDesiredStateConfiguration
    Import-Module -Name xActiveDirectory
    Import-Module -Name NetworkingDsc
    Import-Module -Name ActiveDirectoryCSDsc
    Import-Module -Name ComputerManagementDsc
    Import-Module -Name xDnsServer
    
    # Importing All DSC Resources needed for Configuration
    Import-DscResource -Module PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
    Import-DscResource -Module xActiveDirectory
    Import-DscResource -Module ActiveDirectoryCSDsc
    Import-DscResource -Module ComputerManagementDsc
    Import-DscResource -Module xDnsServer
    
    # Node Configuration block, since processing directly on DC using localhost
    Node 'localhost' {

      Script DisableIESecurity
      {
        SetScript = 
        {
          $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
          $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
          Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
          Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
        }
        GetScript =  { @{} }
        TestScript = { $false }
      }
      
      Script DisableFeedback
      {
        SetScript = 
        {
          New-Item -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
          Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Siuf\Rules" -Name NumberOfSIUFInPeriod -Value 0 -Force | Out-Null
          if ((Get-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Siuf\Rules" -Name PeriodInNanoSeconds -ErrorAction SilentlyContinue) -ne $null) 
          { 
            Remove-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Siuf\Rules" -Name PeriodInNanoSeconds 
          }
        }
        GetScript =  { @{} }
        TestScript = { $false }
      }

      Script DisableUpdates
      {
        SetScript = 
        {
          Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1
        }
        GetScript =  { @{} }
        TestScript = { $false }
      }
      
      # Renaming Primary Adapter in order to Static the IP for AD installation
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'Primary'
            MacAddress = $MacAddress
        }

        # Setting DNS Server on Primary Interface to point to our existing DNS server
        DnsServerAddress DnsServerAddress {
            Address = $DNSServer
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn = '[NetAdapterName]RenameNetAdapterPrimary'
        }
            
        # Wait for AD Domain to be up and running
        xWaitForADDomain WaitForPrimaryDC {
            DomainName = $DomainDnsName
            RetryCount = 600
            RetryIntervalSec = 30
            RebootRetryCount = 10
            DependsOn = '[DnsServerAddress]DnsServerAddress'
        }

        TimeZone TimeZone{
            IsSingleInstance = 'Yes'
            TimeZone         = $InstanceTimeZone
        }
        
        # Rename Computer and Join Domain
        Computer JoinDomain {
            Name = $ThisDCNetBIOSName
            DomainName = $DomainDnsName
            Credential = $Credentials
            DependsOn = "[xWaitForADDomain]WaitForPrimaryDC"
        }
        
        # Adding Needed Windows Features
        WindowsFeature DNS {
            Ensure = "Present"
            Name = "DNS"
            IncludeAllSubFeature = $true
        }
        
        WindowsFeature AD-Domain-Services {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[WindowsFeature]DNS"
        }
        
        WindowsFeature DnsTools {
            Ensure = "Present"
            Name = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
        }
        
        WindowsFeature RSAT-AD-Tools {
            Name = 'RSAT-AD-Tools'
            Ensure = 'Present'
            DependsOn = "[WindowsFeature]AD-Domain-Services"
        }
        
        WindowsFeature RSAT-ADDS {
            Ensure = "Present"
            Name = "RSAT-ADDS"
            DependsOn = "[WindowsFeature]AD-Domain-Services"
        }
        
        WindowsFeature RSAT-ADDS-Tools {
            Name = 'RSAT-ADDS-Tools'
            Ensure = 'Present'
            DependsOn = "[WindowsFeature]RSAT-ADDS"
        }

        WindowsFeature GPOTools {
            Ensure = "Present"
            Name = "GPMC"
            DependsOn = "[WindowsFeature]DNS"
        }

        WindowsFeature DFSTools {
            Ensure = "Present"
            Name = "RSAT-DFS-Mgmt-Con"
            DependsOn = "[WindowsFeature]DNS"
        }

        # Promoting Node as Secondary DC
        xADDomainController SecondaryDC {
            DomainName = $DomainDnsName
            DomainAdministratorCredential = $Credentials
            SafemodeAdministratorPassword = $Credentials
            DependsOn = @("[WindowsFeature]AD-Domain-Services","[Computer]JoinDomain")
        } 
    }
}

# Generating MOF File
ConfigGlgDC -OutputPath 'C:\AWSQuickstart\ConfigGlgDC' -Credentials $Credentials -ConfigurationData $ConfigurationData