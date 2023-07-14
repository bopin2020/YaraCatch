rule dotnet_rubeus
{
    meta:
        author          =   "bopin2020"
        date            =   "2023-07-14"
        threat_level    =   5
        description     =   "detect rubeus"

    strings:
        $ms_blob         =   {0e 0e 1c 1c 07 ?5 [3] 01 1D}
        $guid           =   {27 6? 09 ff [-] 69 ?? 9? f? ?? ?? 8f}
    condition:
        any of them
}
