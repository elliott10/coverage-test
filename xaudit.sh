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
	echo -n "Is the program finished (yes) ?"
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
#echo -e "awk_cmd=\"awk 'NR==3 {gsub(/[%]/,\\\"\\\",\\\$4);print \\\$4}'\"" >> ./$sec.log
#echo -e 'coverage_buf=([0]=init)' >> ./$sec.log
echo -e 'declare -A coverage_buf' >> ./$sec.log

#echo -e 'SendInfo(){
#		echo -e "***** TimeOut *****"
#}

echo -e 'timeout_cmd(){
		waitfor=3
		command=$*
		$command &
		commandpid=$!

		sleep $waitfor ; kill -9 $commandpid  > /dev/null 2>&1
}' >> ./$sec.log
#		( sleep $waitfor ; kill -9 $commandpid  > /dev/null 2>&1 && SendInfo ) &

#		watchdog=$!
#		sleeppid=$PPID
#		wait $commandpid > /dev/null 2>&1

#		kill $sleeppid > /dev/null 2>&1
#}' >> ./$sec.log
echo >> ./$sec.log

echo -e 'zcov_run(){' >> ./$sec.log

echo -e "analyzing the $wpath/audit$sec.log"
sudo cat $wpath/audit$sec.log | \
awk '{if($1 == "type=EXECVE") \
	{printf("timeout_cmd  "); \
	for(i=6;i<=NF;i++) \
	{printf("%s  ",substr($i,4,length($i)))} \
	printf(" > /dev/null 2>&1"); \
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

	print "coverage_buf["$3"]=$(zcov summarize "$3".zcov |awk '\''NR==3 {gsub(/[%]/,\"\",$4);print $4}'\'')" \

	print "rm -f $c_gcda"; \
	print "fi"} \
}' \
>> ./$sec.log

echo >> ./$sec.log
echo -e 'cd $zcov_root' >> ./$sec.log
echo -e 'c_zcov=$(find $zcov_root -name "*.zcov")' >> ./$sec.log
echo -e 'echo -e "zcov merge \n\033[32m$c_zcov\033[0m"' >> ./$sec.log
echo -e 'zcov merge -f /tmp/multiple.zcov $c_zcov' >> ./$sec.log
echo -e 'echo -e "##### summary of coverage data #####"' >> ./$sec.log
echo -e 'zcov summarize /tmp/multiple.zcov' >> ./$sec.log
echo -e 'echo -e "####################################"' >> ./$sec.log

echo -e "mkdir -p /tmp/$sec/all_zcov; mv \$c_zcov /tmp/$sec/all_zcov/" >> ./$sec.log

echo -e "echo -e \"\${!coverage_buf[@]}\" > /tmp/$sec/coverage_buf_ind" >> ./$sec.log
echo -e "echo -e \"\${coverage_buf[@]}\" > /tmp/$sec/coverage_buf_val" >> ./$sec.log

echo -e '} #zcov_run()' >> ./$sec.log

#echo -e 'f_name=$(echo $0 |sed "s/\.log//g")
echo -e 'if [ -d /tmp/$sec ]
then
	echo -e "No run zcov_run()"
	for j in $(cat /tmp/$sec/coverage_buf_ind)
	do
		coverage_buf[$j]=100
	done

else
	echo -e "Run zcov_run()"
	zcov_run

fi' >> ./$sec.log

echo -e "cd /tmp/$sec/all_zcov" >> ./$sec.log

echo -e 'for i in "${!coverage_buf[@]}"
do
	if [ $(echo "${coverage_buf[$i]} < 5" | bc) -eq 1 ]
	then 
		unset coverage_buf[$i]
	fi   
done' >> ./$sec.log
echo -e 'echo -e "Coverage :"' >> ./$sec.log
echo -e 'for c in "${!coverage_buf[@]}"
do
	echo -n "$c.zcov-->${coverage_buf[$c]} "
done' >> ./$sec.log
echo -e 'echo' >> ./$sec.log
echo -e 'echo -e "More test data in /tmp/$sec"' >> ./$sec.log

echo -e 'echo -e "Will continue to test coverage ..."' >> ./$sec.log
echo -e 'read user_input' >> ./$sec.log

echo -e 'echo -e "Calculating 3 largest combination coverage ..."' >> ./$sec.log
echo -e "max_buf=(0 0 0 0 0 0 0 0 0 0)" >> ./$sec.log
echo -e 'for a in ${!coverage_buf[@]}
do
	echo -n "$a.zcov "
	for b in ${!coverage_buf[@]}
	do
		if [ "$b" -eq "$a" ]
		then
			continue
		fi

		for c in ${!coverage_buf[@]}
		do
			if [ "$c" -eq "$a" -o "$c" -eq "$b" ]
			then
				continue
			fi' >> ./$sec.log

echo -e "		#echo -e \"1:\$a.zcov 2:\$b.zcov 3:\$c.zcov\"
			zcov merge -f t.zcov  \$a.zcov \$b.zcov \$c.zcov
			t_zcov=\$(zcov summarize t.zcov |awk 'NR==3 {gsub(/[%]/,\"\",\$4);print \$4}')" >> ./$sec.log

echo -e '		if [ $(echo "$t_zcov > ${max_buf[2]}" | bc) -eq 1 ]
			then
				max_buf[2]=$t_zcov
				max_buf[1]=$a.$b.$c

			else if [ $(echo "$t_zcov > ${max_buf[4]}" | bc) -eq 1 ]
				then
					max_buf[4]=$t_zcov
					max_buf[3]=$a.$b.$c

				else if [ $(echo "$t_zcov > ${max_buf[6]}" | bc) -eq 1 ]
					then
						max_buf[6]=$t_zcov
						max_buf[5]=$a.$b.$c
					fi
				fi
			fi
		done
	done
done
echo 
echo -e "------------------------------"
echo -e "[ ${max_buf[@]} ]"
echo -e "------------------------------"
date +"%F %T"' >> ./$sec.log

echo -e 'echo -e "$0 exit."' >> ./$sec.log

if [ -n "$find_gcda" ]; then
	sudo chmod 755 ./$sec.log
	echo -e "Running ./$sec.log"
	/bin/bash ./$sec.log
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
