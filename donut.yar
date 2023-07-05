rule detect_donut{
    meta:
        description = "detect donut generate shellcode"
        author = "bopin"
        date = "2023-07-05"
        threat_level = 5
    strings:
        $shellcode_x86 = {5A 51 52 81 EC D4 02}
        $shellcode_x64 = {48 83 e4 f0 51 48 89 5c 24 08}
    condition:
        any of them
}
