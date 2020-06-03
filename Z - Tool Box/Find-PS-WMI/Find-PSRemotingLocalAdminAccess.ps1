function Find-PSRemotingLocalAdminAccess 
{
<#
.SYNOPSIS
Use this script to search for local admin access on machines in a domain or local network.

.DESCRIPTION
This function simply runs a PowerShell Remoting command against the sepcified list of computers. Since, by-default, 
we need local administrative access on a computer to run WMI commands, a success for this fucntions 
means local administrative access.

.PARAMETER ComputerFile
File containing list of target computers.

.PARAMETER StopOnSuccess
Stop on first success. 

.EXAMPLE
Find-PSRemotingLocalAdminAccess -ComputerFile C:\test\computers.txt -Verbose

.LINK
https://github.com/samratashok/nishang
http://www.labofapenetrationtester.com/

#>

    [CmdletBinding()] Param(

        [Parameter (Mandatory=$False, Position = 0, ValueFromPipeline=$true)]
        [String]
        $ComputerName,

        [Parameter (Mandatory=$False, Position = 1, ValueFromPipeline=$true)]
        [String]
        $ComputerFile,

        [Parameter ()]
        [Switch]
        $StopOnSucess
    )
    $ErrorActionPreference = "SilentlyContinue"
    #read word list (consider pipeline for performance)
    if ($Computerfile)
    {
        $Computers = Get-Content $Computerfile
    }
    elseif ($ComputerName)
    {
        $Computers = $ComputerName
    }
    else
    {
        # Get a list of all the computers in the domain
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
        $objSearcher.Filter = "(&(sAMAccountType=805306369))"
        $Computers = $objSearcher.FindAll() | %{$_.properties.dnshostname}

    }
	
	    #clear error listing
	    $Error.clear()
	
	    #run the test
        Write-Verbose 'Trying to run a command parallely on provided computers list using PSRemoting .'
        Invoke-Command -ScriptBlock {hostname} -ComputerName $Computers -ErrorAction SilentlyContinue
	
	    #put the first error into a variable (best practice)
	    $ourerror = $error[0]
	
	    # if there is no error, then we were successfull, else, was it a username or password error? if it wasn't username/password incorrect, something else is wrong so break the look
	    if ($ourerror -eq $null) 
        {
		    "The current user has Local Admin access on: $Computer"
            if ($StopOnSucess)
            {
		        break
            }
	    } 
        elseif (-not $ourerror.Exception.Message.Contains("Access is denied.")) 
        {
		    Write-Warning "Something went wrong. Check the settings, confirm hostname etc, $($ourerror.Exception.Message)"
	    } 
        else 
        {
		    Write-Debug "$($ourerror.Exception.Message)"
	    }	
}