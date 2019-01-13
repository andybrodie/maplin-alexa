@echo off
setlocal

set jsonFile="%~dp0powersockets.json"
set topicName=homeautomation/power/config
set host=wensum.ddns.net
set port=8883
set cachain="%~dp0..\publisher\ca-chain.cert.pem"
set cert="%~dp0..\publisher\HomeAutomationMQTTPublisher.cert.pem"
set key="%~dp0..\publisher\HomeAutomationMQTTPublisher.key.pem"

echo Publishing %jsonFile% to %host%:%port%/%topicName%

"c:\Program Files\mosquitto\mosquitto_pub.exe" -h %host% -p %port% -t %topicName% -f %jsonFile% -q 1 -r --cafile %cachain% --cert %cert% --key %key%