rule detect_donut{
    meta:
        description = "detect donut generate shellcode"
        author = "bopin"
        date = "2023-07-05"
        threat_level = 5
    strings:
        $shellcode_x86 			= {5A 51 52 81 EC D4 02}
        $shellcode_x64 			= {48 83 e4 f0 51 48 89 5c 24 08}
	// indistinct
	// 1. wild-cards 通配符   some bytes are unknown   placeholder characters is ?
	$shellcode_x64_wild_cards 	= { ?8 ?9 5c 24 0? 48 }
	// 2. not operators ~ 4.3 yara支持 非运算  即第一个字节不是0x48 
	$shellcode_x64_not_operators 	= { ~48 89 5c 24 08 ~48 }
	// 3. 可变长度和内容的字符块  - 长度跳过相当于 填充min max 任意个??    [6] 允许固定长度 这样更精确  [10-] [-]  infinite
	$shellcode_x64_jump_bytes	= {48 89 5c [100-1000] c1 c3}
	// 4. alternatives 逻辑或					 匹配48 89 5c   48 89 4c
	$shellcode_x64_alternative 	= {48 (89 | 88) (5c | 4c) }
	
	// 5. 文本字符串  大小写敏感		nocase 关键字说明不区分大小写
	$donut_string_ascii = "donut" nocase
	// 6. wide 关键字 unicode字符串的检查   ascii  支持多种方式  xor
	$donut_string_unicode = "donut" wide ascii
	
	// 7. xor string  默认会使用0x00 - 0xff 256逐个异或
	// yara 3.11开始 支持  xor(0x01-0xff)   xor(min,max)
	$donut_string_xor 		= "donut" xor

	// 8. base64  
	$donut_string_base 		= "donut" base64

	// mov xx,rbx(5c)  rbp(6c) rdi(7c)
	// e8 call [address]
	$shellcode_x64_final 		= {48 89 5c [-] e8 34 2e 00 00}

	
    condition:
        any of them
}
