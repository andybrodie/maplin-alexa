@echo off

pushd .

if EXIST "%~dp0package\paho_mqtt-1.4.0-py3.6.egg-info" (
    echo "Skipping PAHO MQTT as paho_mqtt-1.4.0-py3.6.egg-info already available"
) ELSE (
    pip install paho-mqtt --target "%~dp0package"
)

cd "%~dp0package"
zip -r9 ..\..\PowerSocketAlexaLambdaFunction.zip .
cd "%~dp0"
zip -r9 ..\PowerSocketAlexaLambdaFunction.zip *.pem *.py

popd