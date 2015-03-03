var fs = require('fs');
ft = require('file-tail').startTailing('/var/log/secure');
var shell = require('shelljs');
var bufferString;

var listOfIpAddresses = [];

var ipRegEx = /\d+\.\d+\.\d+\.\d+/;

var timeToCheck = process.argv[2];
var timeBeforeBan = process.argv[3];

if(!process.argv[2] || !process.argv[3]){
  console.log("Usage: node ips.js timesToCheckBeforeBanning timeBeforeBanInSeconds");
  process.exit(1);
}

// Read file for the first time
/*
fs.readFile('/var/log/secure', function(error, data){
  if(error){
    console.log('Spock Died!');

  } else{
    bufferString = data.toString();

  }

})

fs.close();
*/

var logObject = function(ipAddress, primaryDateTimeOfFirstViolation){
    this.ipAddress = ipAddress;
    this.dateTime = [];
    this.timeToCheck = process.argv[2];

    this.dateTime[0] = primaryDateTimeOfFirstViolation;

    this.addViolation = function(dateTimeOfViolation){
      // we add a violation to the datetime array here

      this.dateTime.push(dateTimeOfViolation);
      this.checkIfBan();
    }

    this.checkIfBan = function(){
      // check last 3 date Time's that they violated and see if
      // we need to ban them

    if(this.dateTime.length > timeToCheck){
      var lastLog = this.dateTime[this.dateTime.length - 1];
      var firstLog = this.dateTime[this.dateTime.length - 1 - timeToCheck];
      var timeDifference = (lastLog - firstLog) / 1000;

        if(timeDifference <= timeBeforeBan){
          shell.exec("iptables -A INPUT -s " + this.ipAddress + " -j DROP");
          console.log(this.ipAddress + " got his fucking ass banned bitch!");
        }
      }


    }

    function banIP(){

    }

    function banIP(xAmountOfTimeToBan){
      //this is where we run ipTables to ban the IP for X amount of time
    }

}

ft.on('line', function(line){
    bufferString += line;
    if(line.indexOf('Failed') > -1){
      var ip = line.match(ipRegEx);

      if(!listOfIpAddresses[ip[0]]){

        var lobj = new logObject(ip[0], new Date());
        listOfIpAddresses[ip[0]] = lobj;
      }
      else{
        listOfIpAddresses[ip[0]].addViolation(new Date());
      }
    }

});
