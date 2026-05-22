/*
 * Baseline IR YARA rules — minimal starter set.
 * Replace / extend with your team's tested rules.
 *
 * License: Apache-2.0
 */

rule SuspiciousCloudCredentialString
{
    meta:
        author      = "Devel Group · Red Spears Labs"
        description = "Strings that look like AWS access keys or Azure SAS tokens in arbitrary file content"
        severity    = "medium"
    strings:
        $aws_akid   = /AKIA[0-9A-Z]{16}/
        $aws_secret = "aws_secret_access_key" nocase
        $aws_secret_alt = "aws-secret-access-key" nocase
        $azure_sas  = "sig=" ascii
    condition:
        any of them
}

rule LinuxReverseShellOneLiner
{
    meta:
        author      = "Devel Group · Red Spears Labs"
        description = "Common reverse-shell one-liners (bash/python/nc)"
        severity    = "high"
    strings:
        $bash_tcp   = "/dev/tcp/"
        $python_rs  = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
        $nc_rs_a    = "nc -e /bin/sh"
        $nc_rs_b    = "nc -e /bin/bash"
        $nc_rs_c    = "nc.traditional -e /bin/sh"
        $nc_rs_d    = "nc.traditional -e /bin/bash"
    condition:
        any of them
}

rule SuspiciousCryptoMinerStrings
{
    meta:
        author      = "Devel Group · Red Spears Labs"
        description = "Cryptominer indicators (XMRig, pool addresses, donate-level toggles)"
        severity    = "high"
    strings:
        $xmrig      = "xmrig" nocase
        $pool_arg   = "--coin"
        $donate     = "--donate-level"
    condition:
        2 of them
}
