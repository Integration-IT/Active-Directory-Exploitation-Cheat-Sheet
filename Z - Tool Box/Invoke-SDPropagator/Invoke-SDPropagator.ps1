
function Invoke-SDPropagator 
<#
.Description 
Invoke the SDPropagator on the current domain (users domain) 

.Parameter ShowProgress
Display progress and wait for sdpropagation to complete use -showprogress:$false to not wait for propagation to complete.

.Parameter TimeoutMinutes
The number of minutes to wait for SDPropagation to start

.Parameter Domain
Can be used to target remote domains - Domain Admin access is required, so this may not actually be possible.
#>
{
    [CmdletBinding()]Param
    ([switch]$showProgress=$true,
    $timeoutMinutes=1,
    [string]$Domain,
    [string]
    [ValidateSet ("RunProtectAdminGroupsTask","FixUpInheritance")]
    $taskname="RunProtectAdminGroupsTask")
    #https://support.microsoft.com/en-us/help/251343/manually-initializing-the-sd-propagator-thread-to-evaluate-inherited-p
    try {
        if ($domain) {$Domain += '/'}
        $PDC =  ([adsi]([adsi]"LDAP://$(([adsi]"LDAP://$(([adsi]"LDAP://$domain`RootDSE").defaultNamingContext)").fsmoroleowner)").parent ).dnshostname 
        Write-Verbose "PDC Located at $PDC"

        $RootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/RootDSE")
        $RootDSE.UsePropertyCache = $false
    
        Write-Verbose "Initiating SD Propogation on $PDC"
        $RootDSE.Put("RunProtectAdminGroupsTask", "1")
        $RootDSE.SetInfo() 

        if ($showProgress){
            Write-Verbose "Checking for start of SD Propagator"
            $FailDetect = (get-date).AddMinutes($timeoutMinutes)
            $RuntimeQueue = 0
            $RuntimeMax = 0
            $InvokeDetected = $false            
            
            while (($invokeDetected -eq $false -and  (get-date) -lt $FailDetect) -or ($InvokeDetected -eq $true -and $RuntimeQueue -gt 0)){
                $RuntimeQUeue = (get-counter -counter '\directoryservices(ntds)\ds security descriptor propagator runtime queue' -ComputerName $PDC).countersamples.cookedvalue
                if ($RuntimeQueue -gt $RuntimeMax){
                    $InvokeDetected = $true
                    $RuntimeMax = $RuntimeQueue
                }
                if ($InvokeDetected) {
                    Write-Progress -Activity "Invoke-SDPropagator on $PDC" -Status "Waiting for SDPropagator to finish" -PercentComplete ((($runTimeMax - $RuntimeQueue)/($runtimemax)) * 100)
                } else {
                    Write-Progress -Activity "Invoke-SDPropagator on $PDC" -Status "Waiting for SDPropagator to start" -SecondsRemaining ($FailDetect - (get-date)).totalseconds
                }
                start-sleep -seconds .5
            }
        }
    } catch {
        Write-Error "Unable to complete SD Propogation because $_"
    }
}