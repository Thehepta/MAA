# MAA

IDA microcode analysis assistant

```
如果安装了需要先卸载
hcli plugin uninstall MMA

安装
hcli plugin install  https://github.com/Thehepta/MAA
```





# unsupport
写入内存记录为符号的功能暂时不支持
call 调用函数为作为一个单独的无法解析的符号,
call_help没有处理, call help指令例子  atomic_store
```angular2html
call   !atomic_store <fast:"unsigned __int8" #0.1,"unsigned __int8 *" &($byte_A5BE4).8>.0 ; 0000BC0C
```
直接当成无法解析的符号返回


## 单位实时计算
按照顺序实时从前向后实时计算执行，然后把两个环境合并，存在向前合并和向后合并的问题


### 向后追踪
向后追踪顺序是 4 -> 3 -> 2 -> 1
4块未定义变量在3中定义了，4块中所以依赖这个未定义变量的expr都需要使用3中定义的值进行替换


### 向前执行
执行顺序是1 -> 2 -> 3 -> 4，
符号重复定义：一个符号在前面使用了，但是没有找到定义，在后面有定义了，在后面进行符求解的时候，这个符号未定义之前的计算，是否替换成了他定义的值，应该实在他定义以后的计算替换为他的值，他定义之前的计算，是上一个相同符号的值



