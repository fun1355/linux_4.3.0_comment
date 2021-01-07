#!/bin/bash
inputdir="xiebaoyou"
cd $inputdir
for i in $(ls) 
do
	enca -L zh_CN -x UTF-8 $i
done



