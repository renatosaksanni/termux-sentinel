/*
 * Threats aimed at the Termux environment itself.
 *
 * A Linux userland on a phone is a target in its own right: shell droppers,
 * reverse shells, and miners arrive as plain text and never touch the Android
 * package layer, so nothing in the Android rules would ever see them.
 */

rule shell_pipe_to_interpreter {
    meta:
        severity    = "HIGH"
        family      = "dropper"
        description = "Downloads a remote script and pipes it straight into a shell"
        action      = "Read the script before running it. Never execute a URL you have not inspected."
    strings:
        $c1 = /curl\s+[^\n|]{0,120}\|\s*(ba)?sh/ nocase
        $c2 = /wget\s+[^\n|]{0,120}(-O\s*-|-qO-)\s*\|\s*(ba)?sh/ nocase
        $c3 = /fetch\s+-o\s*-\s+[^\n|]{0,120}\|\s*(ba)?sh/ nocase
    condition:
        any of them
}

rule shell_reverse_shell {
    meta:
        severity    = "CRITICAL"
        family      = "backdoor"
        description = "Opens an interactive shell back to a remote host"
        action      = "Delete this file and check for scheduled tasks or startup entries that run it."
    strings:
        $b1 = "bash -i >& /dev/tcp/"
        $b2 = "sh -i >& /dev/tcp/"
        $nc1 = /nc\s+(-[a-zA-Z]+\s+)*-e\s*\/bin\/(ba)?sh/
        $py1 = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
        $py2 = "pty.spawn"
        $py3 = "subprocess.call([\"/bin/sh\""
    condition:
        any of ($b1, $b2, $nc1) or ($py1 and ($py2 or $py3))
}

rule cryptominer_config {
    meta:
        severity    = "HIGH"
        family      = "miner"
        description = "Mining pool configuration, which drains the battery and overheats the phone"
        action      = "Delete the file and any service or cron entry that launches it."
    strings:
        $s1 = "stratum+tcp://"
        $s2 = "stratum+ssl://"
        $x1 = "xmrig"
        $x2 = "randomx"
        $p1 = "--donate-level"
        $p2 = "cryptonight"
    condition:
        any of ($s*) or 2 of ($x*, $p*)
}

rule obfuscated_shell_payload {
    meta:
        severity    = "MEDIUM"
        family      = "obfuscation"
        description = "Base64 blob decoded and executed inline, used to hide a payload from casual reading"
        action      = "Decode the blob and read it before allowing the script to run."
    strings:
        $e1 = /echo\s+[A-Za-z0-9+\/=]{60,}\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh/
        $e2 = /base64\s+-d\s*<<<\s*["']?[A-Za-z0-9+\/=]{60,}/
        $e3 = "eval $(base64 -d"
        $p1 = "exec(__import__('base64').b64decode"
    condition:
        any of them
}

rule termux_credential_harvest {
    meta:
        severity    = "HIGH"
        family      = "infostealer"
        description = "Reads SSH keys, tokens, or shell history and sends them to a remote endpoint"
        action      = "Rotate every key and token stored on this device."
    strings:
        $t1 = ".ssh/id_rsa"
        $t2 = ".ssh/id_ed25519"
        $t3 = ".gitconfig"
        $t4 = ".bash_history"
        $t5 = ".netrc"
        $x1 = "api.telegram.org/bot"
        $x2 = "pastebin.com/api/api_post.php"
        $x3 = /curl\s+[^\n]{0,80}-F\s+["']?file=@/
    condition:
        2 of ($t*) and any of ($x*)
}

rule persistence_via_shell_profile {
    meta:
        severity    = "MEDIUM"
        family      = "persistence"
        description = "Appends a startup command to a shell profile so it runs on every login"
        action      = "Inspect ~/.bashrc, ~/.profile, and ~/.termux/ for commands you did not add."
    strings:
        $p1 = /echo\s+["'][^"'\n]{0,200}["']\s*>>\s*[~$][^\s]{0,40}\/?\.(bashrc|profile|zshrc)/
        $p2 = ">> $HOME/.bashrc"
        $p3 = ">> ~/.termux/termux.properties"
    condition:
        any of them
}
