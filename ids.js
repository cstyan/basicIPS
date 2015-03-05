var fs = require('fs');
ft = require('file-tail').startTailing('/var/log/secure');
var shell = require('shelljs');
var bufferString;

var listOfIpAddresses = [];
var bannedIPs = [];

var ipRegEx = /\d+\.\d+\.\d+\.\d+/;

var timeToCheck = process.argv[2];
var timeBeforeBan = process.argv[3];
var unbanTime = process.argv[4]

if(!process.argv[2] || !process.argv[3]){
    console.log("Usage: node ips.js timesToCheckBeforeBanning timeBeforeBanInSeconds timeToBanForInSeconds");
    process.exit(1);
}

setInterval(function(){
    //check to see if we should unban people
    currentTime = new Date();
    for(var index in bannedIPs){
        var indexTime = bannedIPs[index];
        var difference = currentTime - indexTime;
        if(difference > unbanTime){
            console.log("Unbanning " + index + ".");
            shell.exec("iptables -D INPUT -s " + index + " -j DROP");
            bannedIPs.splice(index, 1);
        }
    }
}, 5000);

var logObject = function(ipAddress, primaryDateTimeOfFirstViolation){
    this.ipAddress = ipAddress;
    this.dateTime = [];
    //this.timeToCheck = process.argv[2];

    this.dateTime[0] = primaryDateTimeOfFirstViolation;

    this.addViolation = function(dateTimeOfViolation){
        //we only want to keep the last 10 failed attempts
        if(this.dateTime.length > 10){
            this.dateTime.shift();
        }
        // we add a violation to the datetime array here
        this.dateTime.push(dateTimeOfViolation);
        this.checkIfBan();
    }

    this.checkIfBan = function(){
        // check last n date Time's that they violated and see if
        // we need to ban them
        if(this.dateTime.length > timeToCheck){
            console.log("More attempts than allowed detected.");
            var lastLog = this.dateTime[this.dateTime.length - 1];
            var firstLog = this.dateTime[this.dateTime.length - 1 - timeToCheck];
            var timeDifference = (lastLog - firstLog) / 1000;
            //if difference between last attempt and first of range we want to check
            //is less than the time allowed for failed attempts set by user
            if(timeDifference <= timeBeforeBan){
                shell.exec("iptables -A INPUT -s " + this.ipAddress + " -j DROP");
                console.log(this.ipAddress + " has been banned");
                //add to banned array
                bannedIPs[this.ipAddress] = new Date();
            }

            //check for slow scan
            var countSlowFails = 0;
            //check for slow scan/patterns
            for(var i = 0; i < timeToCheck; i++){
                var timeOne = this.dateTime[this.dateTime.length - 1 - i]
                var timeTwo = this.dateTime[this.dateTime.length - 1 - (i + 1)]
                var timeDifference = (timeOne - timeTwo) / 1000;
                //if the previous time difference is equal to this time difference
                if(timeDifference >= ((timeBeforeBan / timeToCheck) - 1)){
                    console.log("Incrementing countSlowFails.");
                    countSlowFails++;
                    console.log("countSlowFails currently at: " + countSlowFails);
                }
                if(countSlowFails == timeToCheck){
                    shell.exec("iptables -A INPUT -s " + this.ipAddress + " -j DROP");
                    console.log("Slow scan via periodical attempts detected from IP: " + this.ipAddress);
                    console.log(this.ipAddress + " has been banned");
                    //add to banned array
                    this.bannedIPs[this.ipAddress] = new Date()
                    //iptables -D INPUT -s this.ipAddress -j DROP
                }
                prev = timeDifference;
            }
        }
    }

}

ft.on('line', function(line){
    bufferString += line;
    if(line.indexOf('Failed') > -1){
        var ip = line.match(ipRegEx);

        if(!listOfIpAddresses[ip[0]]){

        var lobj = new logObject(ip[0], new Date());
        listOfIpAddresses[ip[0]] = lobj;
    } else {
        listOfIpAddresses[ip[0]].addViolation(new Date());
    }
}

});
