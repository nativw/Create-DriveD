# Create-DriveD.ps1

## Overview
This PowerShell script shrinks the C drive, creates a new partition D, and encrypts it if needed. If the C drive is encrypted, the script uses the MBAM script (`Invoke-MbamClientDeployment.ps1`) from Microsoft to escrow the encryption key to the MBAM server.

## Features
- Shrinks the C drive by a specified amount.
- Creates a new partition D.
- Encrypts the new partition D if the C drive is encrypted.
- Uses the MBAM script to escrow the encryption key to the MBAM server.

## Prerequisites
- Administrative privileges to run the script.
- BitLocker and MBAM configured in your environment.
- Replace the **`<YourRecoveryServiceEndpoint>`** with your real address of the service endpoint in your environment.

## Usage
1. Navigate to the script directory:
    ```powershell
    cd path\to\script
    ```
2. Run the script with the required parameter:
    ```powershell
    .\Create-DriveD.ps1 -TakeFromCinGB <amount in GB>
    ```

## Parameters
- `-TakeFromCinGB`: The amount of space to be taken from the C drive in GB.

## Example
```powershell
.\Create-DriveD.ps1 -TakeFromCinGB 250
```

## Notes
- The script must be run as admin.
- Ensure that there is enough free space on the C drive before running the script.
- The two .ps1 scripts must be in the same folder, or make sure to update the path after the **`-File`** parameter in line 40:
```powershell
Start-Process -FilePath "powershell.exe" -ArgumentList "-File .\Invoke-MbamClientDeployment.ps1 -RecoveryServiceEndpoint <YourRecoveryServiceEndpoint> -EncryptionMethod UNSPECIFIED -EncryptAndEscrowDataVolume -IgnoreEscrowOwnerAuthFailure" -Wait -NoNewWindow
```
