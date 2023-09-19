###########################################################################################################################################
#Title:Checksum - Web Directory Monitoring Script                                                                                         #
#Author: @hackforfood                                                                                                                     #
#Date: September 2023                                                                                                                     #
#Version: 1.0                                                                                                                             #
#                                                                                                                                         #
#Purpose: Gather hash of a folder and then check this against the control hash variable to detect file system changes such as web shells. #
###########################################################################################################################################


# Define variables

#This is the directory you want to monitor
$folderPath = "D:\Program Files (x86)\apache-tomcat-8.0.28-windows-x64\apache-tomcat"

#This is a list of any variables you want to exclude from monitoring
$excludedDirectories = @("\logs", "/otherdir")

#This is the path to the registy item (change if neeeded)
$registryPath = "HKLM:\Software\CyberSecMonitoring"
$keyName = "ControlChecksum"
$valueName = "ControlChecksum"

# Set Computer Name variable and get the current date
$hostname = $env:computername
$GetDate = Get-Date -Format "dd-MM-yyyy"

#This is the path to the log path (Change as necessary)

$logFilePath = "C:\CyberSec\"
$logname = "checksum_$GetDate.log"

#Configure Syslog Details
# Define whether syslog is enabled and then syslog server address and custom port
$syslogenabled = "$true"
$syslogServer = "127.0.0.1" # Replacve with syslog server
$syslogPort = 5140 # Replace with TCP port number for your syslog environment


#######BECAREFUL CHANGING THINGS BELOW HERE ##########




#Declare Functions


# Function to write log messages to a file
function Write-Log {
    param (
        [string]$message
    )

    #Check if log path exists

    if (Test-Path -Path $logFilePath -PathType Container) {
    
} else {
    
        New-Item -Path $logFilePath -ItemType Directory

}

    # Check if the file exists
if (-not (Test-Path -Path $logFilePath\$logname -PathType Leaf)) {
    
    

    New-Item -Path $logFilePath\$logname -ItemType File
   
} else {
    
}
   
    # Get the current date and time for timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Create a log entry with a timestamp
    $logEntry = "$timestamp - $message"

    # Append the log entry to the log file
    $logEntry | Out-File -FilePath $logFilePath\$logname -Append
}

# Function to calculate SHA-256 hash of a file
function FileHashSHA256 {
    param (
        [string]$filePath
    )

    $fileStream = [System.IO.File]::OpenRead($filePath)
    $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hashAlgorithm.ComputeHash($fileStream)
    $hashString = [BitConverter]::ToString($hashBytes) -replace '-'
    $fileStream.Close()

    return $hashString
}

# Define the syslog message format function

function Format-SyslogMessage {
    param (
        [string]$facility,
        [string]$severity,
        [string]$message
    )

    # Get the current timestamp in the required format (RFC3339)
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"

    # Build the syslog message
    $syslogMessage = "$timestamp $hostname message=$message"

    return $syslogMessage
}


##Script Start
#Start Logging

Write-Log "Script Starting"
Write-Log "Syslog enabled: $syslogenabled"

## Get Hashes of Files

# Get a list of files in the folder and its subfolders (excluding specified directories)
$fileList = Get-ChildItem -Path $folderPath -File -Recurse | Where-Object {
    $exclude = $false
    foreach ($excludedDir in $excludedDirectories) {
        
        if ($_.FullName -like "*$excludedDir*") {
          $exclude = $true
            
            break
        }
    }
    !$exclude
    
}

# Sort the file list to ensure consistent hash calculation

$fileList = $fileList | Sort-Object FullName



# Initialize an empty string to store the combined hash
$combinedHash = ""
$hashes = @()

# Calculate the SHA-256 hash for each file and append it to the combined hash
foreach ($file in $fileList) {
    $fileHash = FileHashSHA256 -filePath $file.FullName
    $hashes += $fileHash
}



# Combine the hashes by concatenating them
$combinedHash = $hashes -join ""

# Calculate the SHA-256 hash of the combined hashes
$combinedSHA256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedHash))
$combinedHashString = [BitConverter]::ToString($combinedSHA256) -replace '-'





# Check if the registry path exists
if (Test-Path -Path $registryPath) {
    # The registry path exists, now check if the value exists within it
    $registryItem = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
    
    if ($null -ne $registryItem) {
       
        $ControlChecksum = Get-ItemProperty -Path $registryPath -Name $valueName | Select-Object -ExpandProperty $valueName
        Write-Log "Got Control Checksum $ControlCheckSum"
    } else {
        # The value does not exist
        Write-Log "Registry path $registryPath exists but the value does not - going to create"
        Set-ItemProperty -Path $registryPath -Name $valueName -Value "$combinedHashString"
        Write-Log "Registry Value $valueName created with value $combinedHashString"
        $ControlChecksum = $combinedHashString
    }
} else {
    #The Path and Key doesn't exist going to create
    Write-Log "Registry Path $registryPath does not exists creating this and the value"
    New-Item -Path $registryPath -Force
    Write-Log "Created the following registry path $registryPath"
    Write-Log "Creating Value"
    Set-ItemProperty -Path $registryPath -Name $valueName -Value "$combinedHashString"
    Write-Log "Created $valueName in $registryPath"
    $ControlChecksum = $combinedHashString

}   
    

#Check computed hash against the stored hash.


if ($combinedHashString -ne $ControlChecksum) {
    ##Values are not equal - begin alert
    $message = "File hash for $folderPath on $hostname has changed should be $ControlChecksum but got $combinedHashString "
    Write-Log $message
# Format the syslog message
$syslogMessage = Format-SyslogMessage -facility 1 -severity 1 -message $message

# Check if syslog is enabled
if ($syslogenabled -eq $true) {
## Attempt to send a syslog alert now if enabled##
    try {
    # Create a TCP client and connect to the syslog server
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect($syslogServer, $syslogPort)

    # Get the network stream for writing data
    $networkStream = $tcpClient.GetStream()

    # Convert the syslog message to bytes and send it
    $syslogBytes = [System.Text.Encoding]::UTF8.GetBytes($syslogMessage)
    $networkStream.Write($syslogBytes, 0, $syslogBytes.Length)

    # Close the network stream and the TCP client
    $networkStream.Close()
    $tcpClient.Close()
    Write-Log "Syslog Sent"
}
catch {
    Write-Host "Error: $_"
    $message = "Unable to syslog: $_"
    Write-Log $message
}
} else { 
## Log message not syslogged and continue
   write-log "Syslog is not enabled, no further action has been carried out"
}

} else {
    
    #Hashes are the same, log this and proceed to ending the script

    Write-Log "File hash for $folderPath is the same"
     }

#Log the script end.
Write-Log "Script End"