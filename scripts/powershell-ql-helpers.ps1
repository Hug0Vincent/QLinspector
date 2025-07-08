<#
This code was almost entirely generated with AI because I'm too bad at powershell.
Any suggestions for improvement are greatly appreciated! :)
#>

function Set-CodeQLGlobalPaths {
    <#
    .SYNOPSIS
        Sets global environment variables for the CodeQL and dnSpy-based analysis pipeline.

    .DESCRIPTION
        This function initializes all required global paths for tools and output folders, including:
        - dnSpy CLI path
        - CodeQL CLI path
        - Sources output
        - Databases output
        - SARIF results path
        - CodeQL queries path

    .PARAMETER DnSpyPath
        Optional. Full path to dnSpy.Console.exe.

    .PARAMETER DnSpyOut
        Optional. Directory where dnSpy will output decompiled sources.

    .PARAMETER CodeQLPath
        Optional. Full path to codeql.exe.

    .PARAMETER CodeQLDbOut
        Optional. Root folder where CodeQL will output databases.

    .PARAMETER QueryPath
        Optional. Path to QLinspector C# query folder.

    .PARAMETER SarifOut
        Optional. Output path for SARIF result files.

    .EXAMPLE
        Set-CodeQLGlobalPaths -CodeQLPath "D:\tools\codeql.exe"

    .EXAMPLE
        Set-CodeQLGlobalPaths
    #>

    # default value to match my own values.
    param (
        [string]$DnSpyExCliPath  = "F:\tools\dnSpy-net-win64\dnSpy.Console.exe",
        [string]$DnSpyOut   = "C:\Users\user\Documents\Pentest\RD\Gadgets\Sources\",
        [string]$CodeQLPath = "C:\Users\user\Documents\Pentest\Tools\codeql-bundle\codeql\codeql.exe",
        [string]$CodeQLDbOut = "C:\Users\user\Documents\Pentest\RD\Gadgets\Files\Codeql\Databases",
        [string]$QueryPath   = "F:\tools\QLinspector\ql\csharp\queries\",
        [string]$SarifOut    = "C:\Users\user\Documents\Pentest\RD\Gadgets\Files\Codeql\Sarif"
    )

    $global:DnSpyExCliPath            = $DnSpyExCliPath
    $global:DnSpyOutputFolder         = $DnSpyOut
    $global:CodeQLCliPath             = $CodeQLPath
    $global:CodeQLDatabasesOutputRoot = $CodeQLDbOut
    $global:QLinspectorQueriesPath    = $QueryPath
    $global:SarifOutputRoot           = $SarifOut

    Write-Host "[+] Global CodeQL environment paths set:"
    Write-Host "    dnSpy Path         : $DnSpyExCliPath"
    Write-Host "    dnSpy Output       : $DnSpyOutputFolder"
    Write-Host "    CodeQL Path        : $CodeQLCliPath"
    Write-Host "    CodeQL DB Output   : $CodeQLDatabasesOutputRoot"
    Write-Host "    Query Path         : $QLinspectorQueriesPath"
    Write-Host "    SARIF Output       : $SarifOutputRoot"
}


function Export-DotNetDlls {
    <#
    .SYNOPSIS
    Searches for .NET DLLs in a specified folder and exports their names, versions, and paths to a JSON file.

    .DESCRIPTION
    Recursively scans a folder for .NET assemblies (.dll files), retrieves their names, versions, and full paths, 
    and writes the information to a structured JSON file.

    .PARAMETER RootFolder
    Root directory to search for .NET DLL files.

    .PARAMETER DestinationFile
    Path to the JSON output file where DLL information will be saved.

    .EXAMPLE
    Export-DotNetDlls -RootFolder "C:\Projects" -DestinationFile "C:\output\DllList.json"

    .NOTES
    Non-.NET DLLs are skipped silently.
    #>
    
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
    Write-Host "[+] JSON results will be saved to: $DestinationFile"

    $assemblies = @()
    $seen = @{}

    Get-ChildItem -Path $RootFolder -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $assembly = [System.Reflection.AssemblyName]::GetAssemblyName($_.FullName)
            $name = $assembly.Name.ToLowerInvariant()

            if (-not $seen.ContainsKey($name)) {
                $seen[$name] = $true
                $assemblies += [PSCustomObject]@{
                    Name    = $assembly.Name
                    Version = $assembly.Version.ToString()
                    Path    = $_.FullName
                    QL      = @{}
                }
            }
        } catch {
            # Skip non-.NET DLLs silently
        }
    }

    $result = [PSCustomObject]@{
        rootPath   = $RootFolder
        assemblies = $assemblies
    }

    $json = $result | ConvertTo-Json -Depth 5

    $json | Out-File -FilePath $DestinationFile -Encoding UTF8

    Write-Host "[+] JSON export complete."
}



function Decompile-DllWithDnSpyEx {
    <#
    .SYNOPSIS
    Decompiles a .NET DLL using dnSpy Console and saves the source code.

    .DESCRIPTION
    Uses dnSpy.Console.exe to decompile a .NET DLL and generate a Visual Studio solution in the output folder.

    .PARAMETER DllPath
    Path to the .NET DLL file to decompile.

    .EXAMPLE
    Decompile-DllWithDnSpyEx -DllPath "C:\Projects\MyLibrary.dll"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DllPath
    )

    if (-not (Test-Path $DllPath)) {
        Write-Error "DLL path '$DllPath' does not exist."
        return
    }

    if (-not (Test-Path $DnSpyOutputFolder)) {
        New-Item -ItemType Directory -Path $DnSpyOutputFolder -Force | Out-Null
    }

    $dllName = [System.IO.Path]::GetFileNameWithoutExtension($DllPath)
    $outputFolder = Join-Path -Path $DnSpyOutputFolder -ChildPath $dllName

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
    <#
    .SYNOPSIS
    Creates a CodeQL database from a Visual Studio solution.

    .DESCRIPTION
    Runs CodeQL CLI to generate a database for the C# source code located in the specified folder.

    .PARAMETER SolutionFolder
    Folder containing the .sln file for the project.

    .EXAMPLE
    Create-CodeQLDatabase -SolutionFolder "C:\Decompiled\MyLibrary"
    #>
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
    $outputFolder = Join-Path -Path $CodeQLDatabasesOutputRoot -ChildPath $solutionName

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
    <#
    .SYNOPSIS
    Runs a CodeQL query against a CodeQL database and generates a SARIF report.

    .DESCRIPTION
    Analyzes a CodeQL database using a specified or default query, outputting results in SARIF format.

    .PARAMETER DatabaseFolder
    Path to the CodeQL database folder.

    .PARAMETER QueryPath
    Path to the CodeQL query to run. Defaults to QLinspector.ql if not provided.

    .EXAMPLE
    Run-CodeQLQuery -DatabaseFolder "C:\CodeQL\DBs\MyLibrary"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DatabaseFolder,

        [string]$QueryPath = $QLinspectorQueriesPath
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
    & $CodeQLCliPath database analyze "$DatabaseFolder" "$QueryPath" --no-sarif-add-file-contents --no-sarif-add-snippets --max-paths=1 --format="sarif-latest" --output="$sarifFile"

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] SARIF report saved to: $sarifFile"
        Get-SarifResultCount -SarifPath $sarifFile
    } else {
        Write-Error "[x] CodeQL query failed."
    }
}

function Get-SarifResultCount {
    <#
    .SYNOPSIS
    Counts the number of results in a SARIF report.

    .DESCRIPTION
    Parses a SARIF file and displays the total number of findings.

    .PARAMETER SarifPath
    Path to the SARIF file.

    .EXAMPLE
    Get-SarifResultCount -SarifPath "C:\Reports\MyLibrary.sarif"
    #>
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
    <#
    .SYNOPSIS
        Complete pipeline to decompile a DLL, create a CodeQL database, optionally run a CodeQL query,
        and optionally delete the database afterward.

    .DESCRIPTION
        Decompiles the specified DLL, creates a CodeQL database, and optionally runs a CodeQL query to analyze it.
        You can provide either a direct DLL path or an assembly name present in the JSON file.
        The Delete switch will remove the generated solution and CodeQL database after the query (if any) is run.

    .PARAMETER DllPath
        Full path to the DLL to analyze. Required if using the 'ByDllPath' parameter set.

    .PARAMETER AssemblyName
        Name of the assembly to look up in the JSON file to find the DLL path. Required if using the 'ByAssemblyName' parameter set.

    .PARAMETER JsonPath
        Optional path to the JSON metadata file (used only with AssemblyName lookup).

    .PARAMETER RunQuery
        Indicates whether to run the CodeQL query after creating the database. Defaults to $true.

    .PARAMETER Delete
        If specified, deletes the generated CodeQL database after analysis.

    .EXAMPLE
        Analyze-DllWithCodeQL -DllPath "C:\Projects\MyLibrary.dll"

    .EXAMPLE
        Analyze-DllWithCodeQL -AssemblyName "MyLibrary" -JsonPath ".\assemblies.json" -Delete

    #>
    [CmdletBinding(DefaultParameterSetName = 'ByDllPath')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByDllPath')]
        [string]$DllPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByAssemblyName')]
        [string]$AssemblyName,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByAssemblyName')]
        [string]$JsonPath,

        [Parameter()]
        [bool]$RunQuery = $true,

        [Parameter()]
        [switch]$Delete

    )

    if ($PSCmdlet.ParameterSetName -eq 'ByAssemblyName') {
        if (-not (Test-Path $JsonPath)) {
            Write-Error "JSON metadata file not found: $JsonPath"
            return
        }

        try {
            $json = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
            $match = $json.assemblies | Where-Object { $_.Name -eq $AssemblyName }

            if (-not $match) {
                Write-Error "Assembly '$AssemblyName' not found in JSON file."
                return
            }

            $DllPath = $match.Path
            if (-not (Test-Path $DllPath)) {
                Write-Error "Resolved DLL path '$DllPath' does not exist."
                return
            }

        } catch {
            Write-Error "Failed to parse JSON file: $_"
            return
        }
    }

    $DllName = ([System.Reflection.AssemblyName]::GetAssemblyName((Get-Item $DllPath).FullName)).Name

    Write-Host "[+] Step 1: Decompiling $DllName..."
    Decompile-DllWithDnSpyEx -DllPath $DllPath

    $SolutionFolder = Join-Path -Path $DnSpyOutputFolder -ChildPath $DllName
    Write-Host "[+] Step 2: Creating CodeQL database for $DllName..."
    Create-CodeQLDatabase -SolutionFolder $SolutionFolder

    if ($RunQuery) {
        $DatabaseFolder = Join-Path -Path $CodeQLDatabasesOutputRoot -ChildPath $DllName
        Write-Host "[+] Step 3: Running CodeQL queries on $DllName..."

        Run-CodeQLQuery-And-Update -AssemblyName $DllName -JsonPath $JsonPath -QueryName "DangerousTypeFinder.ql"
        Run-CodeQLQuery-And-Update -AssemblyName $DllName -JsonPath $JsonPath -QueryName "QLinspector.ql"

        if ($Delete -and (Test-Path $DatabaseFolder)) {
            Write-Host "[+] Deleting CodeQL database folder: $DatabaseFolder"
            Remove-Folder-Robust -Path $DatabaseFolder
            Remove-Item -Recurse -Force -Path $SolutionFolder
        }
    } else {
        Write-Host "[+] Step 3: Skipped running CodeQL query."
    }

    Write-Host "[+] Analysis complete for: $DllName"
}

function Analyze-AllAssemblies {
    <#
    .SYNOPSIS
        Analyzes all assemblies listed in a JSON file using CodeQL, skipping already analyzed ones.

    .DESCRIPTION
        This function loads a list of .NET assemblies from a specified JSON file, checks if they
        have already been analyzed (by inspecting the "QL" results section), and runs a CodeQL
        analysis on each unprocessed DLL.

        If a DLL has already been analyzed, the function will skip it. Otherwise, it invokes the 
        analysis and updates the results.

    .PARAMETER JsonPath
        The full path to the assemblies JSON file. It's the output of the Export-DotNetDlls command.

    .EXAMPLE
        Analyze-AllAssemblies -JsonPath ".\assemblies.json"

        Runs CodeQL analysis on all DLLs listed in `assemblies.json`, skipping those already analyzed.

    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonPath
    )

    if (-not (Test-Path $JsonPath)) {
        Write-Error "JSON file not found at path: $JsonPath"
        return
    }

    $jsonContent = Load-Or-Initialize-DllJson -JsonPath $JsonPath

    foreach ($assembly in $jsonContent.assemblies) {
        $dllName = $assembly.Name
        $dllPath = $assembly.Path

        if (-not (Test-Path $dllPath)) {
            Write-Warning "DLL path not found for assembly '$dllName': $dllPath. Skipping."
            continue
        }

        $index = Get-AssemblyIndex -JsonContent $JsonContent -AssemblyName $DllName
    
        if($JsonContent.assemblies[$index].QL."DangerousTypeFinder.ql" -and $JsonContent.assemblies[$index].QL."DangerousTypeFinder.ql"){
            Write-Host "[+] Analysis already done for $DllName, skipping."
            return

        }else{

            Write-Host "[*] Analyzing assembly: $dllName"
            Analyze-DllWithCodeQL -DllPath $dllPath -Delete
        
        }
    }
}


# function for the result file manipulation
function Load-Or-Initialize-DllJson {
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonPath
    )

    if (-Not (Test-Path $JsonPath)) {
        Write-Error "JSON file not found: $JsonPath"
        return $null
    }

    try {
        $jsonContent = Get-Content $JsonPath -Raw | ConvertFrom-Json
        return $jsonContent
    }
    catch {
        Write-Error "Failed to load or parse JSON file: $_"
        return $null
    }
}

function Save-Json {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$JsonObject,

        [Parameter(Mandatory = $true)]
        [string]$JsonPath
    )

    try {
        $JsonObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonPath -Encoding UTF8
        Write-Host "[+] JSON saved to $JsonPath"
    }
    catch {
        Write-Error "Failed to save JSON to $JsonPath. $_"
    }
}



function Add-AssemblyToJson {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$JsonContent,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $existing = $JsonContent.assemblies | Where-Object { $_.Name -eq $Name -and $_.Path -eq $Path }

    if (-not $existing) {
        $assembly = [PSCustomObject]@{
            Name    = $Name
            Version = $Version
            Path    = $Path
            QL      = @{}
        }
        $JsonContent.assemblies += $assembly
    }
}

enum QueryResultStatus {
    OK
    Timeout
    ERROR
}

function Set-QueryStatus {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$JsonContent,

        [Parameter(Mandatory = $true)]
        [string]$AssemblyName,

        [Parameter(Mandatory = $true)]
        [string]$QueryName,

        [Parameter(Mandatory = $true)]
        [QueryResultStatus]$Status
    )

    $index = Get-AssemblyIndex -JsonContent $JsonContent -AssemblyName $AssemblyName 

    if ($null -ne $index) {
        # Direct reference
        $assemblyRef = $JsonContent.assemblies[$index]
        $assemblyRef.QL.$QueryName.ResultStatus = $Status.ToString()

        # Reassign it
        $JsonContent.assemblies[$index] = $assemblyRef
    }
}


function Update-QueryResults {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$JsonContent,

        [Parameter(Mandatory = $true)]
        [string]$AssemblyName,

        [Parameter(Mandatory = $true)]
        [string]$QueryName,

        [Parameter(Mandatory = $true)]
        [string]$SarifPath
    )

    if (-Not (Test-Path $SarifPath)) {
        Write-Error "SARIF file not found: $SarifPath"
        return
    }

    try {
        $sarif = Get-Content $SarifPath -Raw | ConvertFrom-Json
        $results = $sarif.runs[0].results

        $resultCount = 0
        $pathLengths = @()

        if ($results) {
            $resultCount = $results.Count
            foreach ($result in $results) {
                if ($result.codeFlows) {
                    foreach ($flow in $result.codeFlows) {
                        $steps = $flow.threadFlows[0].locations.Count
                        if ($steps -gt 0) {
                            $pathLengths += $steps
                        }
                    }
                }
            }
        }

        $shortest = $pathLengths | Sort-Object | Select-Object -First 20

        $index = Get-AssemblyIndex -JsonContent $JsonContent -AssemblyName $AssemblyName 

        if ($null -ne $index) {

            $assemblyRef = $JsonContent.assemblies[$index]
            $assemblyRef.QL.$QueryName.NumberOfResults = $resultCount
            $assemblyRef.QL.$QueryName.Top20ShortestPaths = $shortest

            $JsonContent.assemblies[$index] = $assemblyRef
        }
    }
    catch {
        Write-Error "Failed to parse SARIF file: $_"
    }
}



function Run-CodeQLQuery-And-Update {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AssemblyName,

        [Parameter(Mandatory = $true)]
        [string]$JsonPath,

        [Parameter()]
        [string]$QueryName = "QLinspector.ql",

        [Parameter()]
        [int]$TimeoutSeconds = 300
    )

    $jsonExists = Test-Path $JsonPath

    # Construct full query path
    $QueryPath = Join-Path -Path $QLinspectorQueriesPath -ChildPath $QueryName
    if (-not (Test-Path $QueryPath)) {
        Write-Error "Query file not found: $QueryPath"
        return
    }

    $DatabaseFolder = Join-Path -Path $CodeQLDatabasesOutputRoot -ChildPath $AssemblyName
    $SarifFile = Join-Path -Path $SarifOutputRoot -ChildPath "$AssemblyName.sarif"

    if (-not (Test-Path $DatabaseFolder)) {
        Write-Error "CodeQL database folder not found: $DatabaseFolder"
        return
    }

    if (-not (Test-Path $SarifOutputRoot)) {
        New-Item -ItemType Directory -Path $SarifOutputRoot -Force | Out-Null
    }

    $skipQuery = $false

    if ($jsonExists) {

        # Load JSON
        $JsonContent = Load-Or-Initialize-DllJson -JsonPath $JsonPath
        if (-not $JsonContent) {
            Write-Error "Failed to load JSON, aborting."
            return
        }

        # Find Assembly Entry
        $index = Get-AssemblyIndex -JsonContent $JsonContent -AssemblyName $AssemblyName 
        if ($index -eq $null) {
            Write-Error "Assembly '$AssemblyName' not found in JSON."
            return
        }

        # Create 'QL' if missing or not PSCustomObject
        if (-not $JsonContent.assemblies[$index].PSObject.Properties['QL'] -or
            -not ($JsonContent.assemblies[$index].QL -is [PSCustomObject])) {
            $JsonContent.assemblies[$index] | Add-Member -MemberType NoteProperty -Name 'QL' -Value ([PSCustomObject]@{}) -Force
        }

        # Create QueryName entry inside QL if missing or not PSCustomObject
        if (-not $JsonContent.assemblies[$index].QL.PSObject.Properties[$QueryName] -or
            -not ($JsonContent.assemblies[$index].QL.$QueryName -is [PSCustomObject])) {

            $queryResultObject = [PSCustomObject]@{
                Top20ShortestPaths = @{}
                ResultStatus       = ''
                NumberOfResults    = 0
            }
            $JsonContent.assemblies[$index].QL | Add-Member -MemberType NoteProperty -Name $QueryName -Value $queryResultObject -Force
        }

        # Check if results already exist
        if ($JsonContent.assemblies[$index].QL.$QueryName.ResultStatus) {
            Write-Host "[*] Results already exist for '$QueryName' on assembly '$AssemblyName'. Skipping."
            return
        }
    }

    if (-not $skipQuery) {
        $status = Invoke-CodeQLQuery -DatabaseFolder $DatabaseFolder -QueryPath $QueryPath -SarifFile $SarifFile -TimeoutSeconds $TimeoutSeconds    
    }

    if ($jsonExists) {
        Set-QueryStatus -JsonContent $JsonContent -AssemblyName $AssemblyName -QueryName $QueryName -Status $status
        if ($status -eq [QueryResultStatus]::OK) {
            Update-QueryResults -JsonContent $JsonContent -AssemblyName $AssemblyName -QueryName $QueryName -SarifPath $SarifFile
        }

        # Save updated JSON
        Save-Json -JsonObject $JsonContent -JsonPath $JsonPath
    }

    if ($status -eq [QueryResultStatus]::OK) {
        Write-Host "[+] Query $QueryName completed for '$AssemblyName'."
    }
    elseif ($status -eq [QueryResultStatus]::Timeout) {
        Write-Error "[x] Query $QueryName timed out for '$AssemblyName'."
    }
    else {
        Write-Error "[x] Query $QueryName failed for '$AssemblyName'."
    }
}



function Invoke-CodeQLQuery {
    <#
    .SYNOPSIS
        Executes a CodeQL query against a specified database and outputs results to a SARIF file.

    .DESCRIPTION
        This function invokes the CodeQL CLI to run a query on a specified CodeQL database.
        It formats the output as SARIF and writes it to a specified file. It also handles timeouts
        and basic error checking, returning a result status indicating success, timeout, or failure.

    .PARAMETER DatabaseFolder
        The path to the CodeQL database folder (e.g., output of `codeql database create`).

    .PARAMETER QueryPath
        The full path to the CodeQL query (`.ql`) file you want to run.

    .PARAMETER SarifFile
        The output SARIF file path where the query results should be saved.

    .PARAMETER TimeoutSeconds
        (Optional) Timeout in seconds for the CodeQL query to complete. Default is 3600 (1 hour).

    .EXAMPLE
        Invoke-CodeQLQuery -DatabaseFolder "C:\CodeQL\DBs\MyApp" -QueryPath ".\QL\FindVulns.ql" -SarifFile ".\Results\output.sarif"

        Runs the `FindVulns.ql` query on the CodeQL database for "MyApp", and writes results to `output.sarif`.

    .RETURNS
        A [QueryResultStatus] enum indicating:
            - OK: Query succeeded
            - Timeout: Query exceeded the allowed time
            - Error: Query failed

    .NOTES
        This function requires that `$CodeQLCliPath` be set to the full path of the `codeql` executable.
        Ensure that the database and query are compatible with each other (language, schema, etc.).

    #>
    param (
        [string]$DatabaseFolder,
        [string]$QueryPath,
        [string]$SarifFile,
        [int]$TimeoutSeconds = 3600  # 1 hour default
    )

    if (-not (Test-Path $DatabaseFolder)) {
        Write-Error "CodeQL database folder not found: $DatabaseFolder"
        return [QueryResultStatus]::Error
    }
    if (-not (Test-Path $QueryPath)) {
        Write-Error "Query file not found: $QueryPath"
        return [QueryResultStatus]::Error
    }

    $DatabaseFolder=(Get-Item $DatabaseFolder).FullName
    $QueryPath=(Get-Item $QueryPath).FullName

    if (-not (Test-Path $SarifFile)) {
        New-Item -ItemType File -Path $SarifFile -Force | Out-Null
    }

    $SarifFile = (Get-Item $SarifFile).FullName

    $escapedDatabase = $DatabaseFolder.Replace('"', '""')
    $escapedQuery = $QueryPath.Replace('"', '""')
    $escapedSarif = $SarifFile.Replace('"', '""')

    $arguments = "database analyze `"$escapedDatabase`" `"$escapedQuery`" --no-sarif-add-file-contents --no-sarif-add-snippets --max-paths=1 --format=sarif-latest --output=`"$escapedSarif`""

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $CodeQLCliPath
    $processInfo.Arguments = $arguments
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    $process.Start() | Out-Null

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    while (-not $process.HasExited) {
        Start-Sleep -Seconds 1
        if ($stopWatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $process.Kill()
            Write-Error "CodeQL query timed out after $TimeoutSeconds seconds."
            return [QueryResultStatus]::Timeout
        }
    }

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()

    if ($process.ExitCode -eq 0) {
        Write-Host "[+] CodeQL query completed successfully."
        if ($stdout) { Write-Host "[Output] $stdout" }
        return [QueryResultStatus]::OK
    }
    else {
        Write-Error "CodeQL query failed with exit code $($process.ExitCode)."
        if ($stderr) { Write-Error "[Error Output] $stderr" }
        return [QueryResultStatus]::Error
    }
}

function Get-AssemblyIndex {
    param (
        [psobject]$JsonContent,
        [string]$AssemblyName
    )
    for ($i = 0; $i -lt $JsonContent.assemblies.Count; $i++) {
        if ($JsonContent.assemblies[$i].Name -eq $AssemblyName) {
            return $i
        }
    }
    return $null
}

# PowerShell Remove-Item command fails when deleting CodeQL databases.
function Remove-Folder-Robust {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Host "[!] Folder not found: $Path"
        return
    }

    $tempEmpty = Join-Path $env:TEMP "empty_dir"

    # Create empty temp folder if needed
    if (-not (Test-Path $tempEmpty)) {
        New-Item -ItemType Directory -Path $tempEmpty | Out-Null
    }

    # Use robocopy to wipe the contents
    robocopy $tempEmpty $Path /MIR /NFL /NDL /NJH /NJS /NC /NS > $null

    # Now remove the empty root
    try {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        Write-Host "[+] Successfully deleted: $Path"
    }
    catch {
        Write-Warning "[-] Failed to remove folder: $Path - $_"
    }
}
