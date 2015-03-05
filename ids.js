// Source File: idps.js - simple IDPS written in Node.js
// Program: IDPS - monitoring the secure logfile
// Functions:
// setInterval - unban checker
// logObject
//  - addViolation
//  - checkIfBan
//  ft.on - monitors log via tail for events (acts as main function)
// Date: March 1, 2015
// Designer: Callum Styan, Jon Eustace
// Programmer: Callum Styan, Jon Eustace

//variables and includes
var fs = require('fs');
ft = require('file-tail').startTailing('/var/log/secure');
var shell = require('shelljs');
var bufferString;

var stream = fs.createWriteStream("log.txt");
stream.once('open', function(fd) {
  stream.write("My first row\n");

//list of IP's that have failed attempts
var listOfIpAddresses = [];
//list of IP's that have been banned
var bannedIPs = [];

var ipRegEx = /\d+\.\d+\.\d+\.\d+/;

//number of attempts
var timeToCheck = process.argv[2];
//time attempts can occur in
var timeBeforeBan = process.argv[3];
//amount of time after some is banned before the can be unbanned
var unbanTime = process.argv[4];
//interval to check for IP's to unban
var unbanInterval = process.argv[5];

if(!process.argv[2] || !process.argv[3]){
    console.log("Usage: node ips.js timesToCheckBeforeBanning timeBeforeBanInSeconds timeToBanForInSeconds intervalToCheckForUnbansInMilliseconds");
    stream.write("Usage: node ips.js timesToCheckBeforeBanning timeBeforeBanInSeconds timeToBanForInSeconds intervalToCheckForUnbansInMilliseconds");
    process.exit(1);
}

// Function: setInterval function
// Interface: function()
//
// Designer: Callum Styan
// Programmer: Callum Styan
//
// Description: This function loops through
// all the banned IP's to see if it is time 
// to unban them.
setInterval(function(){
    currentTime = new Date();
    for(var index in bannedIPs){
        var indexTime = bannedIPs[index];
        var difference = currentTime - indexTime;
        //if difference between current time and time
        //someone was banned, then unban them, son
        if(difference > unbanTime){
            console.log("Unbanning " + index + ".");
            stream.write("Unbanning " + index + "."");
            shell.exec("/usr/sbin/iptables -D INPUT -s " + index + " -j DROP");
            delete bannedIPs[index];
        }
    }
}, unbanInterval);

// Object: logObject - an object with an IP and array of dateTimes (failed logins)
//
// Designer: Jon Eustace
// Programmer: Jon Eustace, Callum Styan
var logObject = function(ipAddress, primaryDateTimeOfFirstViolation){
    this.ipAddress = ipAddress;
    this.dateTime = [];
    //this.timeToCheck = process.argv[2];

    this.dateTime[0] = primaryDateTimeOfFirstViolation;

    // Function: addViolation
    // Interface: function(dateTimeOfViolation)
    //
    // Designer: Jon Eustace
    // Programmer: Jon Eustace
    //
    // Description: This function adds a dateTime to the
    // collection for the object when a failed login attempt
    // event has occurred.
    this.addViolation = function(dateTimeOfViolation){
        //we only want to keep the last 10 failed attempts
        if(this.dateTime.length > 10){
            this.dateTime.shift();
        }
        // we add a violation to the datetime array here
        this.dateTime.push(dateTimeOfViolation);
        this.checkIfBan();
    }

    // Function: checkIfBan
    // Interface: function()
    //
    // Designer: Jon Eustace, Callum Styan
    // Programmer: Jon Eustace, Callum Styan
    //
    // Description: This function checks to see if
    // an IP should be banned.  It checks for both
    // a violation of the normal attempts/time rules
    // as well as a basic slow scan.
    this.checkIfBan = function(){
        // check last n date Time's that they violated and see if
        // we need to ban them
        if(this.dateTime.length > timeToCheck){
            console.log("More attempts than allowed detected on IP: " + this.ipAddress);
            stream.write("More attempts than allowed detected on IP: " + this.ipAddress);
            var lastLog = this.dateTime[this.dateTime.length - 1];
            var firstLog = this.dateTime[this.dateTime.length - 1 - timeToCheck];
            var timeDifference = (lastLog - firstLog) / 1000;
            //if difference between last attempt and first of range we want to check
            //is less than the time allowed for failed attempts set by user
            if(timeDifference <= timeBeforeBan){
                shell.exec("/usr/sbin/iptables -A INPUT -s " + this.ipAddress + " -j DROP");
                console.log(this.ipAddress + " has been banned");
                stream.write(this.ipAddress + " has been banned");
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
                    countSlowFails = countSlowFails + 1;
                }
                if(countSlowFails >= timeToCheck){
                    shell.exec("/usr/sbin/iptables -A INPUT -s " + this.ipAddress + " -j DROP");
                    console.log("Slow scan via periodical attempts detected from IP: " + this.ipAddress);
                    console.log(this.ipAddress + " has been banned");
                    stream.write("Slow scan via periodical attempts detected from IP: " + this.ipAddress);
                    stream.write(this.ipAddress + " has been banned");
                    //add to banned array
                    bannedIPs[this.ipAddress] = new Date();
                }
                prev = timeDifference;
            }
        }
    }
}

// Function: ft.on - for each line from tail
// Interface: function(line)
//
// Designer: Jon Eustace
// Programmer: Jon Eustace
//
// Description: This function checks each line
// from the file tail object for the Failed keyword
// and the IP address that caused the event.
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

stream.end();
});
