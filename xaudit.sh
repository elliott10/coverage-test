#!/bin/bash

if [ $# -ne 1 ]; then
	echo -e "Usage: $0 DetectPath"
	exit
fi

for cmd_ in auditctl ausearch zcov date
do
	which $cmd_ > /dev/null 2>&1
	if [ $? -ne 0 ]; then
	echo -e "\"$cmd_\" command does not exist!"
	exit
	fi
done

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

echo  '#!/bin/bash' > ./$sec.log
echo  '#../configure --disable-nls CFLAGS="-g -fprofile-arcs -ftest-coverage"' >> ./$sec.log
echo -e "\nzcov_root=$wpath" >> ./$sec.log
echo -e "sec=$sec" >> ./$sec.log
#echo -e "awk_cmd=\"awk 'NR==3 {gsub(/[%]/,\\\"\\\",\\\$4);print \\\$4}'\"" >> ./$sec.log
#echo -e 'coverage_buf=([0]=init)' >> ./$sec.log
echo  'declare -A coverage_buf' >> ./$sec.log

#echo -e 'SendInfo(){
#		echo -e "***** TimeOut *****"
#}

echo  'timeout_cmd(){
		waitfor=2
		command=$*
		$command &
		commandpid=$!

		( sleep $waitfor ; kill -9 $commandpid  > /dev/null 2>&1 )

}' >> ./$sec.log
#		( sleep $waitfor ; kill -9 $commandpid  > /dev/null 2>&1 && SendInfo ) &

#		watchdog=$!
#		sleeppid=$PPID
#		wait $commandpid > /dev/null 2>&1

#		kill $sleeppid > /dev/null 2>&1
#}' >> ./$sec.log
echo >> ./$sec.log

echo  'zcov_run(){' >> ./$sec.log

echo -e "analyzing the $wpath/audit$sec.log"
sudo cat $wpath/audit$sec.log | \
awk '{if($1 == "type=EXECVE") \
	{gsub(/[:.()]/,"",$3); \
	printf("exe_%d=(",$3); \
	for(i=6;i<=NF;i++) \
	{printf("%s ",substr($i,4,length($i)))} \
	printf(" )\n")} \

	else if($1 == "type=CWD") \
	{print "#####"; \
	gsub(/[:.()]/,"",$3); \

	printf("cwd_%d=",$3); \
	printf("(cd %s \";\")\n",substr($5,5,length($5)))} \

	else if($1 == "type=SYSCALL") \
	{gsub(/[:.()]/,"",$3); \

	print "all_cmd"$3"=(\"${cwd_"$3"[@]}\" \"${exe_"$3"[@]}\")"; \
	print "${cwd_"$3"[@]}"; \
	print "echo -e \"${exe_"$3"[@]}\""
	print "timeout_cmd ${exe_"$3"[@]} > /dev/null 2>&1"; \
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
echo  'cd $zcov_root' >> ./$sec.log
echo  'c_zcov=$(find $zcov_root -name "*.zcov")' >> ./$sec.log
echo  'echo -e "zcov merge \n$c_zcov"' >> ./$sec.log
echo  'zcov merge -f /tmp/multiple.zcov $c_zcov' >> ./$sec.log
echo  'echo -e "##### summary of coverage data #####"' >> ./$sec.log
echo  'zcov summarize /tmp/multiple.zcov' >> ./$sec.log
echo  'echo -e "####################################"' >> ./$sec.log

echo  'mkdir -p /tmp/$sec/all_zcov; mv $c_zcov /tmp/$sec/all_zcov/' >> ./$sec.log

echo  'echo -e "${!coverage_buf[@]}" > /tmp/$sec/coverage_buf_index' >> ./$sec.log
echo  'echo -e "${coverage_buf[@]}" > /tmp/$sec/coverage_buf_value' >> ./$sec.log
echo  '} #zcov_run()' >> ./$sec.log

#echo -e 'f_name=$(echo $0 |sed "s/\.log//g")
echo  'if [ -d /tmp/$sec ]
then
	echo -e "No run zcov_run()"

	coverage_value=(`cat /tmp/$sec/coverage_buf_value`)
	value_tmp=0

	for j in $(cat /tmp/$sec/coverage_buf_index)
	do
		coverage_buf[$j]=${coverage_value[$value_tmp]}
		let "value_tmp+=1"
	done

else
	echo -e "Run zcov_run()"
	zcov_run

fi' >> ./$sec.log

echo  'cd /tmp/$sec/all_zcov' >> ./$sec.log

echo  'for i in ${!coverage_buf[@]}
do
	if [ $(echo "${coverage_buf[$i]} < 5" | bc) -eq 1 ]
	then 
		unset coverage_buf[$i]
	fi   
done' >> ./$sec.log
echo  'echo -e "Coverage :"' >> ./$sec.log

echo  'for c in ${!coverage_buf[@]}
do
	eval echo -e "$c.zcov ${coverage_buf[$c]} \\\033[32m\${all_cmd$c[@]}\\\033[0m" >> /tmp/$sec/tmp_info
done' >> ./$sec.log
echo 'sort -n -k 2,2 /tmp/$sec/tmp_info; rm /tmp/$sec/tmp_info' >> ./$sec.log
echo  'echo -e "####################################"' >> ./$sec.log
echo  'echo' >> ./$sec.log
echo  'echo -e "More test data in /tmp/$sec"' >> ./$sec.log

echo  'echo -e "Will continue to test coverage ..."' >> ./$sec.log
#pause break
#echo  'read user_input' >> ./$sec.log

echo  'echo -e "Calculating 3 largest combination coverage ..."' >> ./$sec.log
echo  'max_buf=(0 0 0 0 0)' >> ./$sec.log
echo  'for a in ${!coverage_buf[@]}
do
	#echo -n "$a  "
	echo -n "."
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

echo  '		if [ $(echo "$t_zcov > ${max_buf[0]}" | bc) -eq 1 ]
			then
				max_buf[1]=$a
				max_buf[2]=$b
				max_buf[3]=$c
				max_buf[0]=$t_zcov
			fi
		done
	done
done
echo 
echo -e "------------------------------"
echo -e "[ ${max_buf[@]} ]"
eval echo -e "${max_buf[1]}.zcov \\\033[32m\${all_cmd${max_buf[1]}[@]}\\\033[0m"
eval echo -e "${max_buf[2]}.zcov \\\033[32m\${all_cmd${max_buf[2]}[@]}\\\033[0m"
eval echo -e "${max_buf[3]}.zcov \\\033[32m\${all_cmd${max_buf[3]}[@]}\\\033[0m"
echo -e "------------------------------"
date +"%F %T"' >> ./$sec.log

echo  'echo -e "$0 exit."' >> ./$sec.log

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
