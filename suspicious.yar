rule Suspicious_PowerShell {
    meta:
        description = "Detects PowerShell scripts downloading files"
        author = "Sidharth"
        date = "2026-05-03"
    strings:
        $ps = "powershell" nocase
        $download = "downloadfile" nocase
        $webrequest = "webrequest" nocase
        $http = "http://" nocase
        $https = "https://" nocase
    condition:
        ($ps and $http) or ($ps and $download) or ($ps and $webrequest)
}

rule Suspicious_Executable_Strings {
    meta:
        description = "Detects suspicious strings in executables"
        author = "Sidharth"
        date = "2026-05-03"
    strings:
        $cmd = "cmd.exe" nocase
        $reg_add = "reg add" nocase
        $persist = "persistence" nocase
        $admin = "admin" nocase
        $hidden = "hidden" nocase
        $download = "downloadfile" nocase
    condition:
        3 of them and filesize < 10MB
}

rule Crypto_Wallet_Stealer {
    meta:
        description = "Detects strings commonly found in crypto stealers"
        author = "Sidharth"
        date = "2026-05-03"
    strings:
        $wallet = "wallet" nocase
        $seed = "seed phrase" nocase
        $private_key = "private key" nocase
        $metamask = "metamask" nocase
        $exodus = "exodus" nocase
        $phantom = "phantom" nocase
    condition:
        2 of them
}