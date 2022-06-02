<#
This will mitigate CVE-2022-30190 (follina MSDT) zeroday according to the recommandation of Micro$oft
https://www.heise.de/news/Zero-Day-Luecke-in-MS-Office-Microsoft-gibt-Empfehlungen-7126993.html

This script must be run with administrative (or SYSTEM) privileges

D. Maienhöfer, 2022/06
#>

param(
    [switch]$revert, # will revert the changes. Might be used when M$ has released a patch 
    [string]$backuppath="C:\temp\follina-mitigate", # The path, where the reg-backup should be stored
    [string]$backupfilename="msdt_follina_bak.reg", # The filename to where the reg-backup should be written
    [string]$logfile="C:\temp\folina-mitigate.log" # logfile
)

function log([String]$message, [String]$file, [int]$type=0){
    <#Types:
    0=Info
    1=Warning
    2=Error
    3=<empty>
    #>
    # Create Logdirectory if it doesn't exist yet
    $path=Split-Path -Path $file
    if (!(Test-Path -Path $path)){
        New-Item -ItemType Directory -Path $path -Force
    }

    $typemsg="(INFO) "
    if ($type -eq 1){
        $typemsg="(WARNING) "
    }
    elseif ($type -gt 1){
        $typemsg="(ERROR) "
    }    
    $scriptName = $MyInvocation.ScriptName.Replace((Split-Path $MyInvocation.ScriptName),'').TrimStart('').TrimStart('\')
    if ($type -le 2){
        $message=(Get-Date -Format G)+" ("+$scriptname+"): "+$typemsg+$message
    }    
    try {
        if ($type -lt 1){
            Write-Host $message
        }
        elseif ($type -eq 1) {
            Write-Warning $message
        }
        elseif ($type -eq 2) {
            Write-Error $message
        }
        elseif ($type -gt 2){
            Write-Host $message
        }        
        $message | Out-File -Encoding utf8 -FilePath $file -Append
    }
    catch {
        Write-Error "Unable to make a log entry."
    }
}

function gracefulexit([int]$exitcode) {
    log -file $logfile -message ("Script ended. Exitcode is " + $exitcode) -type 0
    exit($exitcode)
}

# Main
log -message "`r`n" -file $logfile -type 3

# Revert-Mode
if ($revert){
    log -message "Script started in revert-mode..." -file $logfile -type 0    

    [System.IO.FileInfo]$bakfil = [System.IO.FileInfo]($backuppath.TrimEnd('\')+"\"+$backupfilename.trim('\'))
    log -message ("Searching for backup-file `""+$bakfil.FullName+"`"") -file $logfile -type 0

    if(!$bakfil.Exists){    
        log -message ("Unable to find Backupfile `""+$bakfil.FullName+"`". Aborting.") -file $logfile -type 2
        gracefulexit(5)        
    }
    log -message ("Backupfile `""+$bakfil.FullName+"`" found.") -file $logfile -type 0

    # File found. restoring registry key
    log -message ("Restoring registry-backup") -file $logfile -type 0
    try {        
        $bakfil.FullName
        log -message ("Restoring Registry-Key `""+$bakfil.FullName+"`"") -file $logfile -type 0
        Invoke-Command {reg import $bakfil.FullName} # reimport the key
    }
    catch {
        log -message ("Unable to restore Registry-Key => " + $_) -file $logfile -type 2
        gracefulexit(4)
    }
    gracefulexit(0)
}

###################

# Normal-Mode
log -message "Script started in normal-mode..." -file $logfile -type 0

# find and safe the registry key
if (!(Test-Path $backuppath)){
    try {
        new-item -ItemType Directory -Path $backuppath
    }
    catch {
        log -message ("Unable to create backup-directory `""+$backuppath+"`". Aborting.") -file $logfile -type 2
        gracefulexit(1)
    }
}

if (!(Test-Path -path "Registry::HKEY_CLASSES_ROOT\ms-msdt")){
    log -message ("Registrykey doesn't exist. It has possibly been removed before. Aborting.") -file $logfile -type 2
    gracefulexit(2)
}

[System.IO.FileInfo]$bakfil = [System.IO.FileInfo]($backuppath.TrimEnd('\')+"\"+$backupfilename.trim('\'))
if($bakfil.Exists){    
    log -message ("Backupfile `""+$bakfil.FullName+"`" already exists and will be overwritten!") -file $logfile -type 1    
}

log -message ("Exporting Registry-Key") -file $logfile -type 0
Invoke-Command  {reg export 'HKEY_CLASSES_ROOT\ms-msdt' $bakfil.FullName /y} # Export the registry key. overwrite existing backupfile (if any)
$bakfil.Refresh() # refresh the fileinfo

# Check if the export succeeded
if ($bakfil.Exists){
    log -message ($bakfil.FullName + "exists. Size is:" + $bakfil.Length) -file $logfile -type 0
        
    if ($bakfil.Length -eq 0){        
        log -message ("Backupfile is empty. Aborting.") -file $logfile -type 2
        gracefulexit(3)
    }
    else {
        log -message ("Key has been exported to `""+$bakfil.FullName + "`"") -file $logfile -type 0         
    }

    # Restricting Access to backup-file to administrative users only (to prevent this LPE vector when later reimporting the backup)
    log -message ("Restricting permission on `""+$bakfil.FullName + "`"") -file $logfile -type 0
    $Right = [System.Security.AccessControl.FileSystemRights]::Modify
    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None 
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly  
    $objType = [System.Security.AccessControl.AccessControlType]::Allow 
    
    
    $ACL = Get-ACL -Path $bakfil.FullName   
    $ACL.SetAccessRuleProtection($true,$false)
    
    $objUser = New-Object System.Security.Principal.NTAccount("SYSTEM")     
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
    $ACL.RemoveAccessRuleAll($AccessRule)
    $ACL.AddAccessRule($AccessRule)
    
    $objUser = New-Object System.Security.Principal.NTAccount("Administrator") 
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($objUser, $Right, $InheritanceFlag, $PropagationFlag, $objType) 
    $ACL.AddAccessRule($AccessRule)

    try {
        
        $ACL | Set-Acl -Path $bakfil.FullName
    }
    catch {
        log -message ("Unable to restrict filepermissions on backupfile!" + $_) -file $logfile -type 1
    }
    finally {
        log -message ("Filepermission are `r`n" + (Get-ACL -Path $bakfil.FullName).Access) -file $logfile -type 0        
    }    

    # Remove registry hive
    try {
        log -message ("Removing Registry-Key") -file $logfile -type 0
        Invoke-Command  {reg delete 'HKEY_CLASSES_ROOT\ms-msdt' /f} # Delete the key
    }
    catch {
        log -message ("Unable to delete Registry-Key => " + $_) -file $logfile -type 2
        gracefulexit(4)
    }
}
log -message ("Script finished.") -file $logfile -type 0
gracefulexit(0)
