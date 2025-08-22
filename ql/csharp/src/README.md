<div align="center" style="font-size: 148px;">
  🧙‍♂️
</div>

<h1 align="center">
  QLinspector: C#
</h1>

<p align="center">
   Finding C# gadget chains with CodeQL.
</p>

<p align="center">
<a href="#installation">Installation</a> &nbsp;&bull;&nbsp;
<a href="#usage">Usage</a> &nbsp;&bull;&nbsp;
<a href="#queries">Queries</a> &nbsp;&bull;&nbsp;
<a href="#acknowledgements">Acknowledgements</a>
</p>

<br />

# Installation

```sh
$ git clone https://github.com/synacktiv/QLinspector.git
$ codeql database analyze System.Web --format=sarif-latest --output=System.Web.sarif --search-path=./QLinspector/ synacktiv/qlinspector-csharp
```

# Usage

### Basic usage

You can run this command it will launch `Qlinspector.ql` and `DangerousTypeFinder.ql`:
```sh
$ codeql database analyze System.Web --format=sarif-latest --output=System.Web.sarif --search-path=./QLinspector/ synacktiv/qlinspector-csharp
```

### Advanced usage

[Here](../../scripts/powershell-ql-helpers.ps1) you can find some powershell helpers to automate the process of searching gadgets in multiple DLLs.

> [!NOTE]
> JQ must be downloaded for this.

1) Initialize some global variables:
```powershell
PS F:\> . ./scripts/powershell-ql-helpers.ps1
PS F:\> Set-CodeQLGlobalPaths -DnSpyExCliPath ... -DnSpyOut ... -CodeQLPath ... -CodeQLDbOut ... -QueryPath ./ql/csharp/queries/ -SarifOut ... -JQPath ...
```

1) Gather all dotnet DLLs from a specific path:
```powershell
PS F:\> Export-DotNetDlls -RootFolder "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\" -DestinationFile "C:\output\assemblies.json"
```

1) Loop over all DLLs and run the gadget queries:
```powershell
PS F:\> Analyze-AllAssemblies -JsonPath "C:\output\assemblies.json"
```

This step will loop over each DLLs and perform the following operations:
- Decompile the DLL with DnSpyEx
- Create a codeql database in build mode none
- Run the gadget queries
- Parse the sarif file and update the json file to add information about the analysis

> [!NOTE]
> `Analyze-DllWithCodeQL` can be used to perform this on a single DLL.

# Queries

## `QLinspector.ql`

The main CodeQL query that can be used to find gadget chains.

Here is an example with the `TextFormattingRunProperties` gadget chain:

![TextFormattingRunProperties](../../../img/TextFormattingRunProperties.png)

## `DangerousTypeFinder.ql`

If a type is serializable and extends a dangerous one, it becomes a new gadget. This query finds those types.

Here is an example with the `FormsIdentity` gadget:

![FormsIdentity](../../../img/FormsIdentity.png)


# Acknowledgements

- [@chudyPB](https://x.com/chudypb) for his [research](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf) at Hexacon.
- [@pwntester](https://x.com/pwntester) for [Ysoserial.net](https://github.com/pwntester/ysoserial.net/)
- [@irsdl](https://x.com/irsdl) for all the research on gadget and dotnet like [this one](https://soroush.me/downloadable/use_of_deserialisation_in_dotnet_framework_methods_and_classes.pdf).
- All the finders of gadgets
- The peoples at CodeQL, always helping in the [discussion tab](https://github.com/github/codeql/discussions).