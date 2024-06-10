function Invoke-DumpMDEConfig {
    param (
        [switch]$TableOutput,
        [string]$TableOutputFile = "MDEConfig.txt",
        [switch]$CSVOutput
    )

    Write-Host "[+] Dumping Defender Excluded Paths"
    Query-ExclusionPaths -TableOutput:$TableOutput -TableOutputFile:$TableOutputFile -CSVOutput:$CSVOutput

    Write-Host "[+] Dumping Enabled ASR Rules"
    Query-RegASRRules -TableOutput:$TableOutput -TableOutputFile:$TableOutputFile -CSVOutput:$CSVOutput

    Write-Host "[+] Dumping Allowed Threats"
    Query-AllowedThreats -TableOutput:$TableOutput -TableOutputFile:$TableOutputFile -CSVOutput:$CSVOutput

    Write-Host "[+] Dumping Defender Protection History"
    Query-ProtectionHistory -TableOutput:$TableOutput -TableOutputFile:$TableOutputFile -CSVOutput:$CSVOutput

    Write-Host "[+] Dumping Exploit Guard Protection History"
    Query-ExploitGuardProtectionHistory -TableOutput:$TableOutput -TableOutputFile:$TableOutputFile -CSVOutput:$CSVOutput
 

    Write-Host "[+] Dumping Windows Firewall Exclusions"
    Query-FirewallExclusions -TableOutput:$TableOutput -TableOutputFile:$TableOutputFile -CSVOutput:$CSVOutput

    if ($TableOutput) {
        Write-Host "[+] Defender Config Dumped to $TableOutputFile"
    }
}

function Get-ASRRuleDescriptions {
    return @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block Exploit of Vulnerable Signed Drivers"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Prevent Adobe Reader from creating child processes"
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Prevent all Office applications from creating child processes"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem"
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files unless they meet a prevalence, age, or trusted list criterion"
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially hidden scripts"
        "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
        "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Prevent Office applications from injecting code into other processes"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office Communication Application from Creating Child Processes"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence via WMI event subscription"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block Process Creations from PSExec and WMI Commands"
        "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block computer restarting in safe mode (preview)"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes running from USB"
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block the use of copied or imitated system utilities (preview)"
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block the creation of web shells for servers"
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API Calls from Office Macros"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "How to use advanced ransomware protection"
    }
}

function Query-ExclusionPaths {
    param (
        [switch]$TableOutput,
        [string]$TableOutputFile,
        [switch]$CSVOutput
    )

    try {
        $logName = "Microsoft-Windows-Windows Defender/Operational"
        $query = "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=5007)]]"
        $events = Get-WinEvent -LogName $logName -FilterXPath $query

        $exclusionPaths = foreach ($event in $events) {
            $message = $event.Message
            if ($message -match "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^\s]+)") {
                [PSCustomObject]@{
                    Path = $matches[1]
                    TimeCreated = $event.TimeCreated
                }
            }
        }

        if ($TableOutput) {
            $subject = "[+] Exclusion Paths:"
            $subject | Out-File $TableOutputFile -Append
            $exclusionPaths | Format-Table -AutoSize | Out-File $TableOutputFile -Append
        } elseif ($CSVOutput) {
            Write-Host "[+] Dumped Exclusion Paths to ExclusionPaths.csv"
            $exclusionPaths | Export-Csv -Path "ExclusionPaths.csv" -NoTypeInformation
        } else {
            foreach ($path in $exclusionPaths) {
                $path | Format-List
            }
        }
    } catch {
        Write-Error "Failed to query exclusion paths: $_"
    }
}

function Query-RegASRRules {
    param (
        [switch]$TableOutput,
        [string]$TableOutputFile,
        [switch]$CSVOutput
    )

    try {
        $logName = "Microsoft-Windows-Windows Defender/Operational"
        $query = "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=5007)]]"
        $events = Get-WinEvent -LogName $logName -FilterXPath $query
        $asrDescriptions = Get-ASRRuleDescriptions

        $asrRules = foreach ($event in $events) {
            $message = $event.Message
            if ($message -match "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules\\([0-9A-Fa-f-]+)") {
                $asrRuleId = $matches[1].ToLower()
                $description = if ($asrDescriptions.ContainsKey($asrRuleId)) { $asrDescriptions[$asrRuleId] } else { "Unknown ASR Rule" }
                [PSCustomObject]@{
                    RuleId = $asrRuleId
                    Description = $description
                    TimeCreated = $event.TimeCreated
                }
            }
        }

        if ($TableOutput) {
            $subject = "[+] Enabled ASR Rules:"
            $subject | Out-File $TableOutputFile -Append
            $asrRules | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $TableOutputFile -Append
        } elseif ($CSVOutput) {
            Write-Host "[+] Dumped Enabled ASR Rules to ASRRules.csv"
            $asrRules | Export-Csv -Path "ASRRules.csv" -NoTypeInformation
        } else {
            foreach ($rule in $asrRules) {
                $rule | Format-List
            }
        }
    } catch {
        Write-Error "Failed to query ASR rules: $_"
    }
}

function Query-AllowedThreats {
    param (
        [switch]$TableOutput,
        [string]$TableOutputFile,
        [switch]$CSVOutput
    )

    try {
        $logName = "Microsoft-Windows-Windows Defender/Operational"
        $query = "*[System[(EventID=1117 or EventID=5007)]]"
        $events = Get-WinEvent -LogName $logName -FilterXPath $query
        $threatDetails = @{}
        $allowedThreats = @()

        foreach ($event in $events) {
            $message = $event.ToXml()
            $eventId = $event.Id
            
            if ($eventId -eq 1117) {
                $threatId = Select-String -InputObject $message -Pattern 'threatid=(.+?)&' | ForEach-Object { $_.Matches.Groups[1].Value }
                $toolName = Select-String -InputObject $message -Pattern "<Data Name='Threat Name'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                $path = Select-String -InputObject $message -Pattern "<Data Name='Path'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                if ($threatId) {
                    $threatDetails[$threatId] = @{
                        ToolName = $toolName
                        Path = $path
                    }
                }
            } elseif ($eventId -eq 5007) {
                $newValue = Select-String -InputObject $message -Pattern "<Data Name='New Value'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                if ($newValue -and $newValue -match "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Threats\\ThreatIDDefaultAction" -and $newValue.EndsWith("= 0x6")) {
                    $threatId = Select-String -InputObject $newValue -Pattern "ThreatIDDefaultAction\\(.+?) " | ForEach-Object { $_.Matches.Groups[1].Value }
                    if ($threatDetails[$threatId]) {
                        $timeCreated = Select-String -InputObject $message -Pattern "<TimeCreated SystemTime='(.+?)'" | ForEach-Object { $_.Matches.Groups[1].Value }
                        $timeCreatedUtc = [datetime]::ParseExact($timeCreated, "yyyy-MM-ddTHH:mm:ss.fffffffK", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
                        
                        $allowedThreats += [PSCustomObject]@{
                            ThreatID = $threatId
                            ToolName = $threatDetails[$threatId].ToolName
                            Path = $threatDetails[$threatId].Path
                            TimeCreated = $timeCreatedUtc
                        }
                    }
                }
            }
        }

        if ($TableOutput) {
            $subject = "[+] Allowed Threats:"
            $subject | Out-File $TableOutputFile -Append
            $allowedThreats | Format-Table -AutoSize | Out-File $TableOutputFile -Append
        } elseif ($CSVOutput) {
            Write-Host "[+] Dumped Allowed Threats to AllowedThreats.csv"
            $allowedThreats | Export-Csv -Path "AllowedThreats.csv" -NoTypeInformation
        } else {
            foreach ($threat in $allowedThreats) {
                $threat | Format-List
            }
        }
    } catch {
        Write-Error "Failed to query allowed threats: $_"
    }
}


function Query-ProtectionHistory {
    param (
        [switch]$TableOutput,
        [string]$TableOutputFile,
        [switch]$CSVOutput
    )

    try {
        $logName = "Microsoft-Windows-Windows Defender/Operational"
        $query = "*[System[(EventID=1117)]]"
        $events = Get-WinEvent -LogName $logName -FilterXPath $query

        $protectionHistory = foreach ($event in $events) {
            $message = $event.ToXml()
            $eventId = $event.Id
            
            if ($eventId -eq 1117) {
                $threatName = Select-String -InputObject $message -Pattern "<Data Name='Threat Name'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                $severityName = Select-String -InputObject $message -Pattern "<Data Name='Severity Name'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                $categoryName = Select-String -InputObject $message -Pattern "<Data Name='Category Name'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                $path = Select-String -InputObject $message -Pattern "<Data Name='Path'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                $actionName = Select-String -InputObject $message -Pattern "<Data Name='Action Name'>(.+?)</Data>" | ForEach-Object { $_.Matches.Groups[1].Value }
                $timeCreated = Select-String -InputObject $message -Pattern "<TimeCreated SystemTime='(.+?)'" | ForEach-Object { $_.Matches.Groups[1].Value }
                $timeCreatedUtc = [datetime]::ParseExact($timeCreated, "yyyy-MM-ddTHH:mm:ss.fffffffK", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
                
                [PSCustomObject]@{
                    ThreatName = $threatName
                    Severity = $severityName
                    Category = $categoryName
                    Path = $path
                    ActionTaken = $actionName
                    TimeCreated = $timeCreatedUtc
                }
            }
        }

        if ($TableOutput) {
            $subject = "[+] Protection History:"
            $subject | Out-File $TableOutputFile -Append
            $protectionHistory | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $TableOutputFile -Append
        } elseif ($CSVOutput) {
            Write-Host "[+] Dumped Protection History to ProtectionHistory.csv"
            $protectionHistory | Export-Csv -Path "ProtectionHistory.csv" -NoTypeInformation
        } else {
            foreach ($history in $protectionHistory) {
                $history | Format-List
            }
        }
    } catch {
        Write-Error "Failed to query protection history: $_"
    }
}

function Query-ExploitGuardProtectionHistory {
    param (
        [switch]$TableOutput,
        [string]$TableOutputFile,
        [switch]$CSVOutput
    )

    try {
        $logName = "Microsoft-Windows-Windows Defender/Operational"
        $query = "*[System[(EventID=1121)]]"
        $events = Get-WinEvent -LogName $logName -FilterXPath $query -ErrorAction SilentlyContinue
        $asrDescriptions = Get-ASRRuleDescriptions

        $exploitGuardHistory = foreach ($event in $events) {
            $message = $event.Message
            
            $asrRuleId = if ($message -match "ID: ([0-9A-Fa-f-]+)") { $matches[1] } else { $null }
            $detectionTime = if ($message -match "Detection time: (.+?)\s") { [datetime]$matches[1] } else { $null }
            $user = if ($message -match "User: (.+?)\s") { $matches[1] } else { $null }
            $path = if ($message -match "Path: (.+?)\s") { $matches[1] } else { $null }
            $processName = if ($message -match "Process Name: (.+?)\s") { $matches[1] } else { $null }
            $targetCommandline = if ($message -match "Target Commandline: (.+?)\s") { $matches[1] } else { $null }
            $description = if ($asrRuleId -and $asrDescriptions.ContainsKey($asrRuleId)) { $asrDescriptions[$asrRuleId] } else { "Unknown ASR Rule" }

            [PSCustomObject]@{
                RuleId = $asrRuleId
                Description = $description
                DetectionTime = $detectionTime
                User = $user
                Path = $path
                ProcessName = $processName
                TargetCommandline = $targetCommandline
            }
        }

        if ($TableOutput) {
            $subject = "[+] Exploit Guard Protection History:"
            $subject | Out-File $TableOutputFile -Append
            $exploitGuardHistory | Format-Table -AutoSize | Out-String -Width 4096 | Out-File $TableOutputFile -Append
        } elseif ($CSVOutput) {
            Write-Host "[+] Dumped Exploit Guard Protection History to ExploitGuardProtectionHistory.csv"
            $exploitGuardHistory | Export-Csv -Path "ExploitGuardProtectionHistory.csv" -NoTypeInformation
        } else {
            foreach ($history in $exploitGuardHistory) {
                $history | Format-List
            }
        }
    } catch {
        Write-Error "Failed to query exploit guard protection history: $_"
    }
}


function Query-FirewallExclusions {
    param (
        [switch]$TableOutput,
        [string]$TableOutputFile = "FirewallExclusions.txt",
        [switch]$CSVOutput
    )

    $logName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
    $query = "*[System[(EventID=2099 or EventID=2097)]]"
    $events = Get-WinEvent -LogName $logName -FilterXPath $query

    $firewallExclusions = foreach ($event in $events) {
        $message = $event.Message
        $action = [regex]::Match($message, 'Action:\s*(.+)').Groups[1].Value.Trim()
        if ($action -eq "Allow") {
            [PSCustomObject]@{
                RuleID = [regex]::Match($message, 'Rule ID:\s*(.+)').Groups[1].Value.Trim()
                RuleName = [regex]::Match($message, 'Rule Name:\s*(.+)').Groups[1].Value.Trim()
                ApplicationPath = [regex]::Match($message, 'Application Path:\s*(.+)').Groups[1].Value.Trim()
                Direction = [regex]::Match($message, 'Direction:\s*(.+)').Groups[1].Value.Trim()
                Action = $action
                TimeCreated = $event.TimeCreated
            }
        }
    }

    if ($TableOutput) {
         $subject = "[+] Firewall Exclusions:"
         $subject | Out-File $TableOutputFile -Append
        $firewallExclusions | Format-Table -AutoSize  | Out-String -Width 4096 | Out-File $TableOutputFile -Append
    } elseif ($CSVOutput) {
        Write-Host "[+] Dumped Firewall Exclusions to FirewallExclusions.csv"
        $firewallExclusions | Export-Csv -Path "FirewallExclusions.csv" -NoTypeInformation
    } else {
        foreach ($exclusion in $firewallExclusions) {
            $exclusion | Format-List
        }
    }
}