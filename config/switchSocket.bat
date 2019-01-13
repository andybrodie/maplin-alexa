@echo off

setlocal 
if [%2]==[] goto usage

set topicName=homeautomation/power/action

set json={""scene"":"%1",""action"":""%2""}

echo Publishing JSON to %topicName%: %json%

"c:\Program Files\mosquitto\mosquitto_pub.exe" -h wensum.ddns.net -p 8883 -t %topicName% -m "%json%" -q 1 --cafile ca-chain.cert.pem --cert remotepowersockets.cert.pem --key remotepowersockets.key.pem

goto :eof

:usage
echo "Usage: %0 <device|scene> <on|off>

:eof

endlocal