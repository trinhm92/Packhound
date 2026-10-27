/*
  scs bundled YARA rules: generic supply-chain heuristics (not malware-family signatures).
  For family signatures add a curated set (e.g. YARA Forge "core") to ~/.config/scs/yara/.
*/

rule SCS_Npm_Install_Hook_Download_Exec
{
    meta:
        description = "package.json lifecycle script that pipes a download into a shell"
        author = "scs"
    strings:
        $hook = /"(preinstall|install|postinstall)"\s*:\s*"[^"]{0,300}(curl|wget)[^"]{0,300}\|\s*(ba|z)?sh/
    condition:
        $hook
}

rule SCS_Credential_Harvest_With_Exfil
{
    meta:
        description = "reads developer credentials and references an exfiltration endpoint"
        author = "scs"
    strings:
        $c1 = ".npmrc" ascii wide
        $c2 = ".aws/credentials" ascii wide
        $c3 = ".ssh/id_" ascii wide
        $c4 = "gh auth token" ascii wide
        $c5 = "trufflehog" ascii nocase
        $x1 = "discord.com/api/webhooks" ascii nocase
        $x2 = "api.telegram.org/bot" ascii nocase
        $x3 = "webhook.site" ascii nocase
        $x4 = "pipedream.net" ascii nocase
    condition:
        filesize < 20MB and 2 of ($c*) and any of ($x*)
}

rule SCS_GitHub_Workflow_Secrets_Dump
{
    meta:
        description = "GitHub Actions workflow that serialises every secret"
        author = "scs"
    strings:
        $a = "toJSON(secrets)" ascii
        $b = /(curl|wget|Invoke-WebRequest)[^\n]{0,200}https?:\/\//
    condition:
        $a and $b
}

rule SCS_Python_Pth_Exec_Payload
{
    meta:
        description = ".pth file that executes decoded data"
        author = "scs"
    strings:
        $imp = /import [^\n]{0,400}(b64decode|exec\(|marshal\.loads|zlib\.decompress)/
    condition:
        filesize < 1MB and $imp
}
