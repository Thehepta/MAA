# MAA

IDA microcode analysis assistant


hcli plugin uninstall MMA
hcli plugin install  https://github.com/Thehepta/MAA




# unsupport
写入内存记录为符号的功能暂时不支持
call 调用函数为作为一个单独的无法解析的符号
call_help没有处理, call help指令例子  atomic_store
```angular2html
call   !atomic_store <fast:"unsigned __int8" #0.1,"unsigned __int8 *" &($byte_A5BE4).8>.0 ; 0000BC0C
```
直接当成无法解析的符号返回