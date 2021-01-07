#!/bin/bash
shopt -s expand_aliases
gitlogfile="xiebaoyou.log"
outputdir="xiebaoyou"

mkdir -p $outputdir
i=1
alias gitlogtime='git log --pretty=format:"%h%x09%ad%x09%an%x09%s" --date=short'
gitlogtime > $gitlogfile
for n in $(awk '{ a[i++] = $0 } END { for (j=i-1; j>=0;) print a[j--] }' $gitlogfile | awk -F ' ' '{print $1 }')
do
  git format-patch -1 $n --start-number $i -o $outputdir;
  i=$(($i+1))
done

