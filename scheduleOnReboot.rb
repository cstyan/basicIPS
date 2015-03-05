#get the current file directory
currentDirectory = Dir.pwd

#write current crontab to file
`crontab -l > tempcron`
#echo new job to temp file
`echo "@reboot node #{currentDirectory}/ids.js 5 180 1800 1800" >>tempcron`
#put temp file into crontab
`crontab tempcron`
#remove temp file
`rm tempcron`