
 <#
    .Synopsis
        Invoke-UpdateMimikatzScript created by Hashim Jawad (@ihack4falafel)
    .DESCRIPTION
       Convert x64/x86 powerkatz.dll to Base64 string and then update Invoke-Mimikatz.ps1 script from Empire, see the link https://raw.githubusercontent.com/EmpireProject/Empire/dev/data/module_source/credentials/Invoke-Mimikatz.ps1
    .PARAMETER DllPath
       Path to powerkatz.dll generated via Visual Studio.
    .PARAMETER ScriptPath
       Path to Invoke-Mimikatz.ps1 script.
    .EXAMPLE
       For x86: Invoke-UpdateMimikatzScript -DllPath C:\Users\IEUser\Desktop\powerkatz32.dll -ScriptPath C:\Users\IEUser\Desktop\Invoke-Mimikatz.ps1
       For x64: Invoke-UpdateMimikatzScript -DllPath C:\Users\IEUser\Desktop\powerkatz64.dll -ScriptPath C:\Users\IEUser\Desktop\Invoke-Mimikatz.ps1
    .NOTES
        - Download the latest and greatest Mimikatz from https://github.com/gentilkiwi/mimikatz
        - Open the solution file in VS 2017 and install required updates if any
        - Under build>Configuration Manager make sure to update the Configuration to "Second_Release_PowerShell" for x64/x86
        - Build it and then feed the compiled powerkatz.dll to -DllPath in Invoke-UpdateMimikatzScript along with the path to Invoke-Mimikatz.ps1
#>

<# Reference: https://gallery.technet.microsoft.com/scriptcenter/Identify-16-bit-32-bit-and-522eae75 #>
function Get-ExecutableType
{

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]
        $Path
    )

    try
    {
        try
        {
            $stream = New-Object System.IO.FileStream(
                $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path),
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )
        }
        catch
        {
            throw "Error opening file $Path for Read: $($_.Exception.Message)"
        }

        $exeType = 'Unknown'
        
        if ([System.IO.Path]::GetExtension($Path) -eq '.COM')
        {
            # 16-bit .COM files may not have an MS-DOS header.  We'll assume that any .COM file with no header
            # is a 16-bit executable, even though it may technically be a non-executable file that has been
            # given a .COM extension for some reason.

            $exeType = '16-bit'
        }

        $bytes = New-Object byte[](4)

        if ($stream.Length -ge 64 -and
            $stream.Read($bytes, 0, 2) -eq 2 -and
            $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
        {
            $exeType = '16-bit'

            if ($stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) -eq 0x3C -and
                $stream.Read($bytes, 0, 4) -eq 4)
            {
                if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 4) }
                $peHeaderOffset = [System.BitConverter]::ToUInt32($bytes, 0)

                if ($stream.Length -ge $peHeaderOffset + 6 -and
                    $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) -eq $peHeaderOffset -and
                    $stream.Read($bytes, 0, 4) -eq 4 -and
                    $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0)
                {
                    $exeType = 'Unknown'

                    if ($stream.Read($bytes, 0, 2) -eq 2)
                    {
                        if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 2) }
                        $machineType = [System.BitConverter]::ToUInt16($bytes, 0)

                        switch ($machineType)
                        {
                            0x014C { $exeType = '32-bit' }
                            0x0200 { $exeType = '64-bit' }
                            0x8664 { $exeType = '64-bit' }
                        }
                    }
                }
            }
        }
        
        return $exeType
    }
    catch
    {
        throw
    }
    finally
    {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    
}

function Invoke-UpdateMimikatzScript {
    [CmdletBinding()]
    param (
        [string] $DllPath, [string] $ScriptPath
    )

    $DllArch = Get-ExecutableType -Path $DllPath;

    if ($DllArch -eq "64-bit"){
        Write-Host "[+] powerkatz.dll is an x64 Architecture";
        Start-Sleep -Seconds 1

        try {
            $ByteArray = [System.IO.File]::ReadAllBytes($DllPath);
        }
        catch {
            throw "Failed to read file. Please ensure that you have permission to the file, and that the file path is correct.";
        }

        if ($ByteArray) {
            $Base64String = [System.Convert]::ToBase64String($ByteArray);
        }
        else {
            throw "$ByteArray is $null.";
        }

        $ErrorActionPreference = "SilentlyContinue"
        $NewString = "PEBytes64 = '" + $Base64String + "'";
        (Get-Content $ScriptPath) | ForEach-Object {$_ -replace "PEBytes64 = '.+", $NewString} | Set-Content $ScriptPath
        Write-Host "[+] Invoke-Mimikatz.ps1 Base64 string has been updated!";
        Start-Sleep -Seconds 1
    }

    elseif($DllArch -eq "32-bit") {
        Write-Host "[+] powerkatz.dll is an x86 Architecture";
        Start-Sleep -Seconds 1
        
        try {
            $ByteArray = [System.IO.File]::ReadAllBytes($DllPath);
        }
        catch {
            throw "Failed to read file. Please ensure that you have permission to the file, and that the file path is correct.";
        }
    
        if ($ByteArray) {
            $Base64String = [System.Convert]::ToBase64String($ByteArray);
        }
        else {
            throw "$ByteArray is $null.";
        }
    
        $ErrorActionPreference = "SilentlyContinue"
        $NewString = "PEBytes32 = '" + $Base64String + "'";
        (Get-Content $ScriptPath) | ForEach-Object {$_ -replace "PEBytes32 = '.+", $NewString} | Set-Content $ScriptPath
        Write-Host "[+] Invoke-Mimikatz.ps1 Base64 string has been updated!";
        Start-Sleep -Seconds 1

        }
    else{
        Write-Host "[+] powerkatz.dll is an unknown Architecture";
        exit
    }
}