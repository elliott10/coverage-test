#!/bin/bash

if [ $# -ne 1 ]; then
	echo -e "Usage: $0 DetectPath"
	exit
fi

echo -e "\n----- START -----\n"

wpath="$1"

#sudo rm -rf /var/log/audit/audit.log
#echo -e "Deleted \"/var/log/audit/audit.log\""

sec=$(date +%s)
sudo auditctl -w $wpath -p x -k "filterkey$sec"   #Insert  a  watch  for the file system object at path.
date +"%F %T"
sudo auditctl -l

while true
do
	echo -n "Is the program finished (ENTER:yes) ?"
	read Arg

	case $Arg in
	Y|y|YES|yes)
	  break;;
	esac
done

#sudo auditctl -W $wpath   #Remove a watch for the file system object at path.
#sudo auditctl -l

#sudo ausearch -f $wpath
sudo ausearch -i -k "filterkey$sec" > $wpath/audit$sec.log
#sudo ausearch -k "filterkey$sec" > $wpath/audit$sec.log
sudo auditctl -D   #Delete all rules and watches.

#sudo cp /var/log/audit/audit.log "$wpath/audit$sec.log"
#echo -e "\n----- END. See file: $wpath/audit$sec.log -----\n"
#grep -E "CWD|EXECVE" $wpath/audit$sec.log > ./$sec.log

echo
echo -e "finding *.gcda in $wpath"
find_gcda=$(find $wpath -name "*.gcda")
rm -f $find_gcda

echo -e '#!/bin/bash' > ./$sec.log
echo -e '#../configure --disable-nls CFLAGS="-g -fprofile-arcs -ftest-coverage"' >> ./$sec.log
echo -e "\nzcov_root=$wpath" >> ./$sec.log
echo -e "sec=$sec" >> ./$sec.log

echo -e 'SendInfo(){
		echo -e "***** TimeOut *****"
}

timeout_cmd(){
		waitfor=3
		command=$*
		$command &
		commandpid=$!

		( sleep $waitfor ; kill -9 $commandpid  > /dev/null 2>&1 && SendInfo ) &

		watchdog=$!
		sleeppid=$PPID
		wait $commandpid > /dev/null 2>&1

		kill $sleeppid > /dev/null 2>&1
}' >> ./$sec.log

echo -e "analyzing the $wpath/audit$sec.log"
sudo cat $wpath/audit$sec.log | \
awk '{if($1 == "type=EXECVE") \
	{printf("timeout_cmd  "); \
	for(i=6;i<=NF;i++) \
	{printf("%s  ",substr($i,4,length($i)))} \
	print ""} \

	else if($1 == "type=CWD") \
	{print "#####"; \
	print "cd",substr($5,5,length($5))} \

	else if($1 == "type=SYSCALL") \
	{gsub(/[:.()]/,"",$3); \

	print ""; \
	print "c_gcda=$(find $zcov_root -name \"*.gcda\")"; \
	print "if [ -n \"$c_gcda\" ]; then"; \
	print "zcov scan "$3".zcov $zcov_root"; \
	print "zcov summarize "$3".zcov >> $zcov_root/$sec.zcov_log"; \
	print "rm -f $c_gcda"; \
	print "fi"} \
}' \
>> ./$sec.log

echo >> ./$sec.log
echo -e 'cd $zcov_root' >> ./$sec.log
echo -e 'c_zcov=$(find $zcov_root -name "*.zcov")' >> ./$sec.log
echo -e 'echo -e "zcov merge \n\033[32m$c_zcov\033[0m"' >> ./$sec.log
echo -e 'zcov merge -f multiple.zcov $c_zcov' >> ./$sec.log
echo -e 'echo -e "##### summary of coverage data #####"' >> ./$sec.log
echo -e 'zcov summarize multiple.zcov' >> ./$sec.log

echo -e 'echo -e "$0 exit"' >> ./$sec.log
echo -e 'exit' >> ./$sec.log

if [ -n "$find_gcda" ]; then
	sudo chmod 755 ./$sec.log
	echo -e "Running ./$sec.log"
	./$sec.log
else
	echo -e "NULL *.gcda file. Please configure in $wpath with \033[32m--disable-nls CFLAGS=\"-g -fprofile-arcs -ftest-coverage\"\033[0m"
fi

#cat ./$sec.log

echo -e "\n----- END. See file: ./$sec.log -----\n"

#echo -e "\033[30m 黑色字 \033[0m" 
#echo -e "\033[31m 红色字 \033[0m" 
#echo -e "\033[32m 绿色字 \033[0m" 
#echo -e "\033[33m 黄色字 \033[0m" 
#echo -e "\033[34m 蓝色字 \033[0m" 
#echo -e "\033[35m 紫色字 \033[0m" 
#echo -e "\033[36m 天蓝字 \033[0m" 
#echo -e "\033[37m 白色字 \033[0m"
