rule dotnet_defendercheck
{
    meta:
        author          =   "bopin2020"
        date            =   "2023-07-14"
        threat_level    =   5
        description     =   "detect defender check"

    strings:
	$global_guid    =   "$3ec9b9a8-0afe-44a7-8b95-7f60e750f042"
        $productname    =   "DefenderCheck" wide ascii   
        $codestr1       =   "NoThreatFound" wide ascii base64     
        $codestr2       =   "ThreatFound" wide ascii base64

        /*
        1. we would like to check blob signature 
        such as the specified offset type was string or int for
        c# binary 
        metadata table blob

        2. search Attribute const variables whatever types are strings or num
        18F9h: 4E 6F 20 74 68 72 65 61 74 20 66 6F 75 6E 64 00  No threat found. 
        1909h: 00 11 01 00 0C 54 68 72 65 61 74 20 66 6F 75 6E  .....Threat foun 
        1919h: 64 00 00 20 01 00 1B 54 68 65 20 66 69 6C 65 20  d.. ...The file  
        1929h: 63 6F 75 6C 64 20 6E 6F 74 20 62 65 20 66 6F 75  could not be fou 
        1939h: 6E 64 00 00 0C 01 00 07 54 69 6D 65 6F 75 74 00  nd......Timeout. 
        1949h: 00 0A 01 00 05 45 72 72 6F 72                    .....Error

        3. metadata stream   #guid
        */
        $ms_blob        =   {04 20 01 01 ?? 08 0? 20 00}
        $bytes1         =   {4e 6f 20 74 [-] 54 68 72 [-] 6e 64 [-] 54 69 [-] 6f 72}
        $guid           =   {89 53 [0-12] DE 50}
    condition:
        any of them
}