# 覆盖率自动测试说明：

例如，测试giflib目录下的程序运行覆盖率。
将能捕捉到giflib目录下所有的进程运行及其参数，如果检测到编译时使用了gcov编译选项，将自动测试每个运行过的进程覆盖率，最后汇总。

1. cd [xaudit.sh PATH] 
  ./xaudit.sh /home/os/giflib #需要SUDO权限

2. cd /home/os/giflib
  makecheck #跑测试用例

3. cd [xaudit.sh PATH]
  yes #目录下运行进程的监测完成
  yes #计算出覆盖率最大的三个测试进程组合

4. 最后测试结果将统计到[xaudit.sh PATH]目录和/home/os/giflib目录下的log文件中。
