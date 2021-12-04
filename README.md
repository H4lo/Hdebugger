# Hdebugger

基于ptrace原理实现的简单linux调试器，目前仅支持x86_64位环境。

## 编译方式

```
git clone https://github.com/H4lo/Hdebugger.git
cd Hdebugger
make
```

## Usage

采用attach附加进程的方式对运行中的程序进行调试：
```
./debug [PID] (debug with root permission)
```

支持命令如下：
```
Attach process '14297' success!
Enter the command(Type help for more.)
>> help
help                            show the help information.
print [addr]                    print the content of the memory address.
set [addr] [content]            fill content to address.
break/c [addr]                  breakpoint in addr.
continue/c                      continue.
next/n                          step over.
exit/q                          exit the debugger.
Enter the command(Type help for more.)
```


### print

打印指定地址中的内存数据：

```
>> print
Enter the address (hex): 7f1be928b020
Enter the len: 100
read memory success!

0x7f1be928b020    61 61 61 61 62 62 62 62 63 63 63 63 64 64 64 64
0x7f1be928b030    65 65 65 65 00 00 00 00 00 00 00 00 00 00 00 00
0x7f1be928b040    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x7f1be928b050    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x7f1be928b060    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x7f1be928b070    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0x7f1be928b080    00 00 00 00
```

### set

设置内存中的数据：

```
>> set
Enter the address (hex): 7f1be928b020
Enter the content (\n to end.): test123
set content to memory success!

Enter the command(Type help for more.)
>> print
Enter the address (hex): 7f1be928b020
Enter the len: 32
read memory success!

0x7f1be928b020    74 65 73 74 31 32 33 62 63 63 63 63 64 64 64 64
0x7f1be928b030    65 65 65 65 00 00 00 00 00 00 00 00 00 00 00 00
Enter the command(Type help for more.)
```

### break

设置断点，当程序触发断点时调试器会接受到SIGTRAP信号：

```
>> b
Enter the address (hex): 12345678
Breakpoint in 12345678
```

### continue

继续运行程序，程序发出的信号都会被调试器接收：

```
>> c
Program got a signal: Segmentation fault
Program is dead, Exit!
```

### step

单步步过指令：

```
>> next
single step success!
```

### info

输出当前的寄存器信息：

```
>> info
RIP: 7fc7eaf41142 Instruction executed: 0
$rax            0x0
$rbx            0x7fc7eb01b980
$rcx            0x7fc7eb07b013
$rdx            0x1000
$rsi            0x7fc7eb07f2b0
$rdi            0x0
$rsp            0x7fffbfbf6138
$rbp            0x7fc7eb01d4a0
$rip            0x7fc7eaf41142

```
