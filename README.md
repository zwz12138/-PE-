# 滴水逆向三期PE部分代码学习
滴水逆向三期PE部分代码
前面一小部分代码参考自https://github.com/123yonghu/-

**注：需要用x86编译**

有些基本函数偷懒没写emmm，也修改了部分，例如

ImageBufferToFileBuffer函数，跳过.textbss节，可以修改vs编译出来的程序注入shellcode

学习过程https://zwz12138.github.io/2022/02/23/PE%E6%96%87%E4%BB%B6%E7%BB%93%E6%9E%84%E5%AD%A6%E4%B9%A0%E9%9A%8F%E8%AE%B0-1/
