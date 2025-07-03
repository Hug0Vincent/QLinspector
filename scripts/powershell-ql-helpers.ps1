
$DnSpyExCliPath = "F:\tools\dnSpy-net-win64\dnSpy.Console.exe"
$OutputPrefixFolder = "C:\Users\user\Documents\Pentest\RD\Gadgets\Sources\"
$CodeQLCliPath = "C:\Users\user\Documents\Pentest\Tools\codeql-bundle\codeql\codeql.exe"
$CodeQLDatabaseOutputRoot = "C:\Users\user\Documents\Pentest\RD\Gadgets\Files\Codeql\Databases"
$DefaultQueryPath = "F:\tools\QLinspector\ql\csharp\queries\QLinspector.ql"
$SarifOutputRoot = "C:\Users\user\Documents\Pentest\RD\Gadgets\Files\Codeql\Sarif"

function Export-DotNetDlls {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RootFolder,

        [Parameter(Mandatory = $true)]
        [string]$DestinationFile
    )

    if (-Not (Test-Path $RootFolder)) {
        Write-Error "The root folder '$RootFolder' does not exist."
        return
    }

    Write-Host "[+] Searching for .NET DLLs under: $RootFolder"
    Write-Host "[+] Results will be saved to: $DestinationFile"

    # Ensure output file is empty
    if (Test-Path $DestinationFile) {
        Clear-Content -Path $DestinationFile
    }

    Get-ChildItem -Path $RootFolder -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $assembly = [System.Reflection.AssemblyName]::GetAssemblyName($_.FullName)
            "$($assembly.Name) - $($assembly.Version) - $($_.FullName)" | Out-File -FilePath $DestinationFile -Append
        } catch {
            # Skip non-.NET DLLs
        }
    }

    Write-Host "[+] Export complete."
}


function Decompile-DllWithDnSpyEx {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DllPath
    )

    if (-not (Test-Path $DllPath)) {
        Write-Error "DLL path '$DllPath' does not exist."
        return
    }

    if (-not (Test-Path $OutputPrefixFolder)) {
        New-Item -ItemType Directory -Path $OutputPrefixFolder -Force | Out-Null
    }

    $dllName = [System.IO.Path]::GetFileNameWithoutExtension($DllPath)
    $outputFolder = Join-Path -Path $OutputPrefixFolder -ChildPath $dllName

    if (-not (Test-Path $outputFolder)) {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    }

    & $DnSpyExCliPath  "$DllPath" -o "$outputFolder" --sln-name "$dllName.sln"

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Solution created at: $outputFolder"
    } else {
        Write-Error "[x] Failed to create solution."
    }
}

function Create-CodeQLDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SolutionFolder
    )

    $slnFile = Get-ChildItem -Path $SolutionFolder -Filter *.sln | Select-Object -First 1

    if (-not $slnFile) {
        Write-Error "No .sln file found in folder: $SolutionFolder"
        return
    }

    $solutionName = [System.IO.Path]::GetFileNameWithoutExtension($slnFile.Name)
    $outputFolder = Join-Path -Path $CodeQLDatabaseOutputRoot -ChildPath $solutionName

    if (-not (Test-Path $outputFolder)) {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    }

    & $CodeQLCliPath database create "$outputFolder" `
        --language=csharp `
        --source-root "$SolutionFolder" `
        --build-mode=none

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] CodeQL database created at: $outputFolder"
    } else {
        Write-Error "[x] Failed to create CodeQL database."
    }
}

function Run-CodeQLQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DatabaseFolder,

        [string]$QueryPath = $DefaultQueryPath
    )

    # Validate database folder
    if (-not (Test-Path $DatabaseFolder)) {
        Write-Error "Database folder '$DatabaseFolder' does not exist."
        return
    }

    # Extract base name from database folder
    $baseName = [System.IO.Path]::GetFileName($DatabaseFolder)
    $sarifFile = Join-Path -Path $SarifOutputRoot -ChildPath "$baseName.sarif"

    # Ensure output folder exists
    if (-not (Test-Path $SarifOutputRoot)) {
        New-Item -ItemType Directory -Path $SarifOutputRoot -Force | Out-Null
    }

    # Run CodeQL analysis
    & $CodeQLCliPath database analyze "$DatabaseFolder" "$QueryPath" --format="sarif-latest" --output="$sarifFile"

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] SARIF report saved to: $sarifFile"
        Get-SarifResultCount -SarifPath $sarifFile
    } else {
        Write-Error "[x] CodeQL query failed."
    }
}

function Get-SarifResultCount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SarifPath
    )

    if (-Not (Test-Path $SarifPath)) {
        Write-Error "SARIF file not found: $SarifPath"
        return
    }

    try {
        $sarifContent = Get-Content $SarifPath -Raw | ConvertFrom-Json

        if ($sarifContent.runs.Count -eq 0 -or -Not $sarifContent.runs[0].results) {
            Write-Host "[+] No results found in SARIF file."
            return 0
        }

        $resultCount = $sarifContent.runs[0].results.Count
        Write-Host "[+] Total results found: $resultCount"
    }
    catch {
        Write-Error "Failed to parse SARIF file: $_"
    }
}


function Analyze-DllWithCodeQL {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DllPath,

        [Parameter()]
        [bool]$RunQuery = $true
    )

    # Get DLL base name
    $DllName = [System.IO.Path]::GetFileNameWithoutExtension($DllPath)

    # Step 1: Decompile DLL
    Write-Host "[+] Step 1: Decompiling $DllName..."
    Decompile-DllWithDnSpyEx -DllPath $DllPath

    # Step 2: Create CodeQL Database
    $SolutionFolder = Join-Path -Path $OutputPrefixFolder -ChildPath $dllName
    Write-Host "[+] Step 2: Creating CodeQL database for $DllName..."
    Create-CodeQLDatabase -SolutionFolder $SolutionFolder

    # Step 3: Conditionally Run CodeQL Query
    if ($RunQuery) {
        $DatabaseFolder = Join-Path -Path $CodeQLDatabaseOutputRoot -ChildPath $DllName
        Write-Host "[+] Step 3: Running CodeQL query on $DllName..."
        Run-CodeQLQuery -DatabaseFolder $DatabaseFolder
    } else {
        Write-Host "[+] Step 3: Skipped running CodeQL query."
    }

    Write-Host "[+] Analysis complete for: $DllName"
}