rule reverse_ssh
{
    meta:
        description = "Detect NHAS Reverse SSH Reverse Shell Client"
        author = "Blackpoint APG"
        date = "04/11/2023"
        reference = "https://github.com/NHAS/reverse_ssh"

    strings:
        $1 = "foreground"
        $2 = "proxy"
        $3 = "fingerprint"
        $4 = "Couldnt get username:"
        $5 = "Couldnt get host name:"
        $6 = "No server key specified, allowing connection to"
        $7 = "Server public key invalid, expected:"
        $8 = "rssh"
        $9 = "Unable to connect to TCP invalid address:"
        $10 = "Got kill command, goodbye"

    condition:
        all of them
}
