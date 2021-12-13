## Log4J Detection and Logging in Windows

You can use this script to log what files have the vulnerability and use the created log files to take action. 


### Usage

Make sure to precreate the destination paths and folders referenced in the control script.
Ensure the appropriate permissions for the folders have been set. 

Update the script in the vars section to the path you created above.

#### Deployment Options

You can deploy this via GPO, running as either a scheduled task or Start Up script.

The script will only run once on each system if running via a GPO.

You could also run this Ad-hoc via PSRemoting. 

Make sure the central logging is set up and the account running the command has permissions to the share.

```markdown
# First we test the storage location for the results file, there will be 2 directories, 
# one for a positive detection and one for negitive detection, I do this so the "scan" will only run once when deployed via group policy
# and you can validate the machines that have run the command etc.

#region Main var declaration
$logName = $env:COMPUTERNAME + "_Log4j.csv"

$mainLogStorage = "\\A_NETWORK_PATH"
$detectionSuccessFolderPath = Join-Path -Path $mainLogStorage -ChildPath "Positive"
$detectionNegativeFolderPath = Join-Path -Path $mainLogStorage -ChildPath "Negative"
# Make sure to create these paths before deployment
$detectionSuccessFullPath = Join-Path -Path $detectionSuccessFolderPath -ChildPath $logName
$detectionNegativeFullPath = Join-Path -Path $detectionNegativeFolderPath -ChildPath $logName

$searchPatten = "JndiLookup.class"
# Finds all logical drives to search 
$localDrives = Get-WMIObject -Class win32_logicaldisk | Where-Object -Property DriveType -eq 3 | Select-Object DeviceID
# Fild type to search
$typesToSearch = "*.jar", "*.war"

#endregion 

# Break if file exists in either negative or positive folder

if ($(Test-Path -Path $detectionSuccessFullPath) -or $(Test-Path -Path $detectionNegativeFullPath)) {
    break
}

# Find all .jar files on the system and determin if the lookup class is being used

$properties = @{
    FileName = "";
    Path     = "N/A";
    Version  = "N/A"
}
# Main loop, searches each logical drive for defined file types and outputs to share
foreach ($drive in $localDrives) {
    Write-Warning -Message "Checking Drive $($drive)"
    $searchFiles = Get-ChildItem -Force -Recurse -Path "$($drive.DeviceID)\" -Include $typesToSearch -ErrorAction SilentlyContinue

    if ($searchFiles.count -gt 0) {
        $detection = $false
        foreach ($file in $searchFiles) {
            $result = $file | Select-String -SimpleMatch $searchPatten
            if ($result) {
                $script:detection = $true
                $obj = New-Object -TypeName psobject -Property $properties
                $obj.FileName = $file.Name
                $Obj.Path = $file.FullName
                $obj.Version = $file.VersionInfo.FileVersion
                $obj | Export-Csv -Path $detectionSuccessFullPath -NoTypeInformation -Append
            }           
        }
        if ($detection -eq $false) {
            $obj = New-Object -TypeName psobject -Property $properties
            $obj.FileName = "Nothing Found - Log4j2 not detected"

            $obj | Export-Csv -Path $detectionNegativeFullPath -NoTypeInformation
        } 
    }
    else {
        $obj = New-Object -TypeName psobject -Property $properties
        $obj.FileName = "Nothing Found - No Jar Files"
        $obj | Export-Csv -Path $detectionNegativeFullPath -NoTypeInformation
    }
}
```
Make sure to check the link for updaters to the script. 
[GitHub Source File](https://github.com/ntatschner/log4j-detection-windows)

I hope this helps someone!

Nigel Tatschner 
