#!/bin/bash

pwd=$(pwd)

crontab -l > tempcron
echo "@reboot /usr/bin/node $pwd/ids.js 5 180 180 180" >> tempcron
crontab tempcron