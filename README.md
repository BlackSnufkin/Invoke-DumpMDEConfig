# DumpMDEConfig PowerShell Script

## Overview
`Invoke-DumpMDEConfig` is a PowerShell script designed to extract and display Microsoft Defender configuration and logs, including excluded paths, enabled ASR rules, allowed threats, protection history, and Exploit Guard protection history. The script provides options to output the data in a table or CSV format.

## Usage

```powershell
# To run the script and output the results in list format:
Invoke-DumpMDEConfig

# To run the script and output the results in table format:
Invoke-DumpMDEConfig -TableOutput

# To run the script and output the results in CSV format:
Invoke-DumpMDEConfig -CSVOutput

# To specify a custom file for table output:
Invoke-DumpMDEConfig -TableOutput -TableOutputFile "CustomFile.txt"
```
## Acknowledgements 

* Thanks to [VakninHai](https://x.com/VakninHai/status/1796628601535652289)
