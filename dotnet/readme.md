# .NET 恶意文件的检测    
> 由于.NET恶意文件的混淆  变形比较容易，给对抗带来了一丝趣味      
> 可以基于.net metadata table 提取某些结构之间的依赖关系作为检测点      
> 比如mimikatz中 LogonSessions功能的交叉引用 这种特征的提取除了修改源码替换相关功能，静态上还是很有效的。        

