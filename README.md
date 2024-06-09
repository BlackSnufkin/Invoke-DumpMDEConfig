# DumpMDEConfig PowerShell Script

## Overview
`DumpMDEConfig` is a PowerShell script designed to extract and display Microsoft Defender configuration and logs, including excluded paths, enabled ASR rules, allowed threats, protection history, and Exploit Guard protection history. The script provides options to output the data in a table or CSV format.

## Usage

```powershell
# To run the script and output the results in table format:
Invoke-DumpMDEConfig -TableOutput

# To run the script and output the results in CSV format:
Invoke-DumpMDEConfig -CSVOutput

# To specify a custom file for table output:
Invoke-DumpMDEConfig -TableOutput -TableOutputFile "CustomFile.txt"
