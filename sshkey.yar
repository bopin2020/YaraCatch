rule sshd_sshkey
{
    meta:
	  description = "memory search sshkey sshielded private key"
	  threat_level = 0
	  author = "bopin"
    strings:
	  // openssh 8.2
	  $a = {00 00 00 00 00 00 00 00 [80] 70 05 00 00 00 00 00 00 [8] 00 40 00 00 00 00 00 00}
    condition:
        any of them
}