<#
.SYNOPSIS
    This script creates a new partition D on the disk by shrinking the C drive.
    It also encrypts the new partition if the C drive is encrypted, and uses the MBAM script from Microsoft to escrow the encryption key to the MBAM server.

.DESCRIPTION
    The script contains two functions:
    1. New-DriveD: Shrinks the C drive by the amount provided in the parameter and creates a new partition D.
    2. Invoke-DDriveEncryption: Checks if the C drive is encrypted and encrypts the new partition D if required. After encryption with BitLocker, it uses the MBAM script from Microsoft to escrow the encryption key to the MBAM server.

.PARAMETER TakeFromCinGB
    The amount of space to be taken from the C drive in GB.

.EXAMPLE
    New-DriveD -TakeFromCinGB 250

.NOTES
    This script must be run as an administrator.
#>

# Check if the script is running with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as an administrator." -ForegroundColor Red
    exit
}

$ComputerName = $env:COMPUTERNAME

function Invoke-DDriveEncryption {
    # Check if partition C is encrypted, then encryption of the new partition is also needed.
    $BitlockerDriveC = Get-Wmiobject -Namespace root\CIMv2\Security\MicrosoftVolumeEncryption -Class Win32_EncryptableVolume -ComputerName $ComputerName -Filter "DriveLetter='C:'"
    $StatusC = $BitLockerDriveC.GetConversionStatus()

    $BitlockerDriveD = Get-Wmiobject -Namespace root\CIMv2\Security\MicrosoftVolumeEncryption -Class Win32_EncryptableVolume -ComputerName $ComputerName -Filter "DriveLetter='D:'"
    $StatusD = $BitLockerDriveD.GetConversionStatus()

    if (($StatusC.ConversionStatus -eq 1 -or $StatusC.ConversionStatus -eq 2) -and ($StatusD.ConversionStatus -ne 1)) {
        # This means that Drive C is fully encrypted, or at least in encryption progress, and D is also not encrypted, so we must encrypt drive D, too
        Write-Host "Starting encryption on drive D. Please wait..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" -ArgumentList "-File .\Invoke-MbamClientDeployment.ps1 -RecoveryServiceEndpoint <YourRecoveryServiceEndpoint> -EncryptionMethod UNSPECIFIED -EncryptAndEscrowDataVolume -IgnoreEscrowOwnerAuthFailure" -Wait -NoNewWindow

        # Wait for encryption to complete
        if ($StatusD.ConversionStatus -eq 2) {
            do {
                Start-Sleep 5
                Write-Host "Encryption progress: $($StatusD.EncryptionPercentage)% completed."
                $BitlockerDriveD = Get-Wmiobject -Namespace root\CIMv2\Security\MicrosoftVolumeEncryption -Class Win32_EncryptableVolume -ComputerName $ComputerName -Filter "DriveLetter='D:'"
                $StatusD = $BitLockerDriveD.GetConversionStatus()
            }
            until ($StatusD.ConversionStatus -eq 1)
            Write-Host "Encryption Completed." -ForegroundColor Yellow
            Write-Host ""
        }
    }
    else {
        Write-Host "Encryption of drive D is not required."
        Write-Host ""
    }
}
function New-DriveD {
    
    param (
        [parameter(Mandatory = $true)]
        [int]$TakeFromCinGB
    )

    # Get all current drive letters
    $currentDrives = Get-PSDrive | Where-Object { $_.Provider.Name -eq 'FileSystem' } | ForEach-Object { $_.Name }

    # Check if there's already drive D
    $driveD = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='D:'"

    if ($driveD -and $driveD.DriveType -eq 3) {
        Write-Host "Drive D already exist."
        Write-Host ""
        return
    }

    # If D drive is a CD-Rom, change the drive letter to the next available one
    if ($driveD -and $driveD.DriveType -eq 5) {
        # Get the next available drive letter
        $nextLetter = [char[]]([int][char]'E'..[int][char]'Z') | Where-Object { $_ -notin $currentDrives } | Select-Object -First 1
        $nextLetter = $nextLetter + ':'
        Write-Host "Changing the drive letter of the CD-Rom. It will be now: "+$nextLetter
        Set-WmiInstance -InputObject ( Get-WmiObject -Class Win32_volume -Filter "DriveLetter = 'd:'" ) -Arguments @{DriveLetter = $nextLetter }
    }

    # Shrink drive C by the amount provided in the parameter
    Write-Host "Shrinking Drive C."
    $size = $TakeFromCinGB * 1024 * 1024 * 1024 # Size in bytes
    $drive = Get-Partition -DriveLetter C
    try {
        $drive | Resize-Partition -Size ($drive.Size - $size)
    }
    catch {
        Write-Host "Error shrinking drive C: $_"
        return
    }

    # Create a new partition in the new space
    Write-Host "Creating the new partition."
    $newPartition = New-Partition -DiskNumber $drive.DiskNumber -UseMaximumSize

    # Format as NTFS and label as 'Data'
    Write-Host "Formatting the new partition."
    Format-Volume -Partition $newPartition -FileSystem NTFS -NewFileSystemLabel 'Data'

    # Assign drive letter D
    Write-Host "Assigning drive letter D to the new partition."
    $newPartition | Set-Partition -NewDriveLetter D

    Write-Host "Partition manipulation completed."
    Write-Host ""

    # Call Invoke-DDriveEncryption to encrypt the new partition if needed
    Invoke-DDriveEncryption
}

# Main script
New-DriveD -TakeFromCinGB 250