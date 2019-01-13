import time
import datetime
import logging
import os
import sys
import json
import base64
import uuid
import ssl
import paho.mqtt.client as mqtt
import paho.mqtt.subscribe as subscribe
import paho.mqtt.publish as publish

# Please confirm that you authorise Slater and Gordon to sign a Statement of Truth on your behalf, confirming that the information you clarify in your email is accurate, has been provided honestly and can be relied on in evidence. Configure logging
logging.basicConfig(
    format='%(asctime)s %(levelname)s %(funcName)s:%(lineno)d %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Power switch configuration, this is global because it's set via an async callback
# delivered as a retained message on the config queue.
switch_config = None

# Set if switch_config cannot be set.
switch_config_error = None

#######################################################################################
# Base64 encoding and decoding routines for strings
#######################################################################################

def b64encode_str(a_string):
    """
    Encodes an arbitrary string as a base 64 ASCII string
    """
    output = base64.b64encode(a_string.encode("UTF-8")).decode('ascii')
    logger.debug("Encoded %s as %s", a_string, output)
    return output


def b64decode_str(b64string):
    """
    Decodes an arbitrary string from a base 64 ASCII string
    """
    output = base64.b64decode(b64string).decode("UTF-8")
    logger.debug("Decoded %s as %s", b64string, output)
    return output

#######################################################################################
# Functions to handle switching devices on and off
#######################################################################################

def handle_switch(mqtt_client, topic, switch_name, turn_on):

    logger.info("Received request to change switch %s to %s",
                switch_name, str(turn_on))

    mqtt_command = json.dumps({
        # Turn the ID back in to the "friendly name" (the only name the MQTT subscriber knows)
        "device": switch_name,
        "action": "on" if turn_on else "off"
    })

    response_message = None

    try:
        logger.info("Sending to topic %s: %s", topic, mqtt_command)
        mqtt_client.publish(topic, mqtt_command, 0)
    except Exception as e:
        logger.exception("Exception thrown when publishing to %s")
        response_message = {"error_type": "INTERNAL_ERROR",
                            "error_message": "Unable to post message to MQTT broker: " + e}

    return response_message


def create_base_error(event, context):
    """
    Creates the template for errors that may be returned by the service.
    """
    token = event["endpoint"]["scope"]["token"]

    error_message = {
        "event": {
            "header": {
                "namespace": "Alexa",
                "name": "ErrorResponse",
                "messageId": str(uuid.uuid4()),
                "payloadVersion": "3"
            },
            "endpoint": {
                "scope": {
                    "type": "BearerToken",
                    "token": token
                },
            },
            "payload": {
            }
        }
    }
    return error_message


def create_error_response(event, context, appliance_id, error_type, error_message):
    """
    Creates an error response for when something goes wrong with a control command.

    See https://developer.amazon.com/docs/device-apis/alexa-errorresponse.html for types of error

    """
    error = create_base_error(event, context)
    error["event"]["endpoint"]["endpointId"] = appliance_id

    correlation_token = event["header"]["correlationToken"]
    error["event"]["header"]["correlationToken"] = correlation_token

    error["event"]["payload"]["type"] = error_type
    error["event"]["payload"]["message"] = error_message

    return error

# Create a connection to the MQTT broker

def create_mqtt_client():
    """
    Creates a connection to the MQTT broker using environment variables for MQQT host, port, TLS trusted certificate chain,
    client certificate file and client key file, along with the cwd which should contain these files.  The envrionent
    variables are: MQTT_HOST, MQTT_PORT, LAMBDA_TASK_ROOT, TLS_CA_FILE, TLS_CLIENT_CERT_FILE, TLS_CLIENT_KEY_FILE.

    Note that this function connects to the broker, so disconnect must be called subsequently.

    Default values for each of these make it easy to test locally.  (Yes, I'm lazy.)
    """

    # Get all these from env vars set inside the lambda job.
    hostname = os.getenv('MQTT_HOST', "wensum.ddns.net")
    port = int(os.getenv('MQTT_PORT', "8883"))

    # AWS will define a "base" path via an environment variable, however use "." if running locally.
    base = os.environ.get('LAMBDA_TASK_ROOT', ".")

    # TLS certificate authority.  This contains the client certificate (first) followed by the chain that will be
    # used to validate the server certificate.  I tried putting these in separate files but it kept rejecting
    # the certificate chain.
    ca_certs = os.path.join(base, os.getenv(
        "TLS_CA_FILE", "ca-chain.cert.pem"))

    client_cert_file = os.path.join(base, os.getenv(
        "TLS_CLIENT_CERT_FILE", "HomeAutomationMQTTPublisher.cert.pem"))

    # The private key that corresponds to the public key in ca_cert that will be used to authenticate the client.
    client_key_file = os.path.join(base, os.getenv(
        "TLS_CLIENT_KEY_FILE", "HomeAutomationMQTTPublisher.key.pem"))

    # Only permit TLS 1.2 or greater.
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.options |= ssl.OP_NO_TLSv1
    client_context.options |= ssl.OP_NO_TLSv1_1

    # This won't work unless the first certificate in the file corresponds to the private key.
    client_context.load_cert_chain(client_cert_file, client_key_file)
    client_context.load_verify_locations(ca_certs)

    # Create an MQTT client object, configure it with the SSL Context we've created.
    client = mqtt.Client()
    client.tls_set_context(client_context)

    logger.debug("Attempting to connect to MQTT broker %s:%s", hostname, port)
    client.connect(hostname, port)
    logger.info("Connected to MQTT broker %s:%s", hostname, port)

    return client

#######################################################################################
# Functions handle device discovery
#######################################################################################


def handle_discover_appliances(event, context, mqtt_client, config_topic):
    """
    Invoked to handle a list of discovered appliances.
    """
    logger.info("Handling discover appliance")

    wait_for_switch_config(mqtt_client, config_topic)

    # Create the basic framework of the response message
    discovery_message = {
        "event": {
            "header": {
                "namespace": "Alexa.Discovery",
                "name": "Discover.Response",
                "payloadVersion": "3",
                "messageId": str(uuid.uuid4())
            },
            "payload": {
                "endpoints": []
            }
        }
    }

    # Now add entries in to the endpoints array, based on the switch configuration

    for device in switch_config["devices"]:
        device_data = {
            # We need a reversible ID because this is what will be sent back to us
            # on a turn on or off request.
            "endpointId": b64encode_str(device),
            "manufacturerName": "Locima Ltd.",
            "friendlyName": device,
            "description": device + " plugged in to a Maplin Power Socket on 434MHz",
            # Smart plug is the closest category, although we don't have the ability to read
            "displayCategories": ["SMARTPLUG"],
            "capabilities": [
                {
                    "type": "AlexaInterface",
                    "interface": "Alexa",
                    "version": "3"
                },
                {
                    "type": "AlexaInterface",
                    "interface": "Alexa.PowerController",
                    "version": "3",
                    "properties": {
                        "supported": [
                            {
                                "name": "powerState"
                            }
                        ],
                        "proactivelyReported": False,  # Against recommendation, but we can't support it
                        "retrievable": False           # We can't read the state using Maplin sockets, it's fire and forget
                    }
                },
            ]
        }

        discovery_message["event"]["payload"]["endpoints"].append(device_data)

    logger.info("Constructed discovery response" +
                json.dumps(discovery_message))
    return discovery_message

#######################################################################################
# Functions to obtain switch configuration
#######################################################################################

def on_config_received(client, userdata, message):
    """
    Callback when the retained config message is received.
    """

    global switch_config

    logger.debug("Received (topic={}, qos={}, retain={}): {}".format(
        message.topic, message.qos, message.retain, message.payload))

    try:
        switch_config = json.loads(message.payload)
    except:
        logging.exception("Failed to parse json. message=%s" % message.payload)
        return False

    logger.info("Configuration loaded in to global var: %s",
                json.dumps(switch_config))


def subscribe_to_config(mqtt_client, config_topic):
    """
    Subscribe to the config topic, where we should pick up a retained message containing
    the configuration of all the switches via the on_config_received callback.

    We only need to call this for a discovery event, if turning things on and off we can
    do it ourselves.
    """

    mqtt_client.message_callback_add(config_topic, on_config_received)
    logger.debug("Subscribing to %s", config_topic)
    mqtt_client.subscribe(config_topic, 0)
    logger.info("Subscribed to %s and registered callback", config_topic)


def wait_for_switch_config(mqtt_client, config_topic):
    """
    Subscribes to the config topic and then Waits for the switch config retained message to be returned.

    We rely on the lambda function timeout from causing this to loop indefinitely.
    """

    subscribe_to_config(mqtt_client, config_topic)

    sleep_duration = 0.1
    mqtt_client.loop_start()

    while (switch_config is None):
        logger.debug("Waiting for config, sleeping for %ss", sleep_duration)
        time.sleep(sleep_duration)

    # We only want the retaining config message, so stop listening now.
    mqtt_client.loop_stop()

    return switch_config


#######################################################################################
# Top-level functions to handle the event from Alexa
#######################################################################################

def process_event(event, context, mqtt_client, base_topic):
    """
    Process the event received.

    Invoked from lambda_function once various set up is done and connection to MQTT client has been
    created.
    """

    # First, work out which type of event has been receieved, then delegate
    # to the appropriate function.
    namespace = event["directive"]["header"]["namespace"]
    name = event["directive"]["header"]["name"]

    # The message we'll end up returning, either: a successful discover, unsuccessful discovery,
    # successful turnon/turnoff or unsucessful turnon/turnoff.
    return_message = None

    if (namespace == "Alexa.Discovery"):
        if (name != "Discover"):
            logger.error(
                "Unexpected event name: %s inside namespace %s", namespace, name)
        return_message = handle_discover_appliances(
            event, context, mqtt_client, base_topic + "/config")
    else:
        if (namespace == "Alexa.PowerController"):
            switch_name = b64decode_str(
                event["directive"]["endpoint"]["endpointId"])
            turnOn = True if name == "TurnOn" else False
            start_time = datetime.datetime.now()
            error = handle_switch(
                mqtt_client, base_topic + "/action", switch_name, turnOn)
            if (error is not None):
                return_message = create_error_response(
                    event, context, switch_name, error["error_type"], error["error_message"])
            else:
                correlation_token = event["directive"]["header"]["correlationToken"]
                access_token = event["directive"]["endpoint"]["scope"]["token"]

                return_message = create_success_response(
                    start_time, correlation_token, access_token, switch_name, "ON" if turnOn else "OFF")
        else:
            logger.error(
                "Unexpected event: %s, returning empty response", json.dumps(event))
            return_message = {}

    return return_message


def create_success_response(start_time, correlation_token, access_token, switch_name, value):
    """

    start_time = when the processing started
    correlation_token = taken from the request
    access_token = taken from the request
    switch_name = the name of the switch that has been changed
    value = ON|OFF
    """

    start_timestamp = start_time.strftime("%Y-%m-%dT%H:%M:%S.00Z")
    latency = int((datetime.datetime.now() -
                   start_time).total_seconds() * 1000)

    response = {
        "context": {
            "properties": [{
                "namespace": "Alexa.PowerController",
                "name": "powerState",
                "value": value,
                "timeOfSample": start_timestamp,
                "uncertaintyInMilliseconds": latency
            },
            {
                "namespace": "Alexa.EndpointHealth",
                "name": "connectivity",
                "value": {
                    "value": "OK"
                },
                "timeOfSample": start_timestamp,
                "uncertaintyInMilliseconds": latency
            }]
        },
        "event": {
            "header": {
                "namespace": "Alexa",
                "name": "Response",
                "payloadVersion": "3",
                "messageId": "abc-123-def-456",
                "correlationToken": correlation_token
            },
            "endpoint": {
                "scope": {
                    "type": "BearerToken",
                    "token": access_token
                },
                "endpointId": b64encode_str(switch_name)
            },
            "payload": {}
        }
    }
    return response

# The entry point for the function inside AWS Lambda, as called from the Alexa skill.


def lambda_handler(event, context):

    logger.debug("Incoming event=%s", json.dumps(event))
    # logger.debug("Incoming context=%s", json.dumps(context))

    # Initialise a connetion to the MQTT broker
    mqtt_client = create_mqtt_client()
    base_topic = os.getenv('MQTT_BASE_TOPIC', "homeautomation/power")

    try:
        # Convert the input Alexa message to the message we're going to post to Mosquitto
        return_message = process_event(event, context, mqtt_client, base_topic)
    finally:
        # No matter what, try to elegantly disconnect from the broker
        logger.debug("Disconnecting from broker")
        mqtt_client.disconnect()
        logger.info("Disconnected from broker")

#    with open("exampleDiscoveryResponse.json") as json_file:  
#        return_message = json.load(json_file)

    logger.info("Returning Python (logging as JSON)\n%s", json.dumps(return_message))

    return return_message

#######################################################################################
# Testing Code
#######################################################################################

if __name__ == "__main__":

    # Runs some tests based on the different types of smart home
    # request that the Alexa Skill can make.

    test_appliance_id = ""

    sample_discovery = {
        "directive": {
            "header": {
                "namespace": "Alexa.Discovery",
                "name": "Discover",
                "payloadVersion": "3",
                "messageId": "1bd5d003-31b9-476f-ad03-71d471922820"
            },
            "payload": {
                "scope": {
                    "type": "BearerToken",
                    "token": "access-token-from-skill"
                }
            }
        }
    }

    sample_turn_on_action = {
        "directive": {
            "header": {
                "namespace": "Alexa.PowerController",
                "name": "TurnOn",
                "payloadVersion": "3",
                "messageId": "1bd5d003-31b9-476f-ad03-71d471922820",
                "correlationToken": "dFMb0z+PgpgdDmluhJ1LddFvSqZ/jCc8ptlAKulUj90jSqg=="
            },
            "endpoint": {
                "scope": {
                    "type": "BearerToken",
                    "token": "access-token-from-skill"
                },
                "endpointId": "Q2hlcnJ5IFRyZWUgTGFtcA==",
                "cookie": {}
            },
            "payload": {}
        }
    }

    sample_turn_off_action = {
        "directive": {
            "header": {
                "namespace": "Alexa.PowerController",
                "name": "TurnOff",
                "payloadVersion": "3",
                "messageId": "1bd5d003-31b9-476f-ad03-71d471922820",
                "correlationToken": "dFMb0z+PgpgdDmluhJ1LddFvSqZ/jCc8ptlAKulUj90jSqg=="
            },
            "endpoint": {
                "scope": {
                    "type": "BearerToken",
                    "token": "access-token-from-skill"
                },
                "endpointId": "Q2hlcnJ5IFRyZWUgTGFtcA==",
                "cookie": {}
            },
            "payload": {}
        }
    }

    context = json.loads("{}")

    print("\nDoing a sample discovery")
    lambda_handler(sample_discovery, context)

    print("\nDoing a turn on")
    lambda_handler(sample_turn_on_action, context)

    print("\nDoing a turn off")
    lambda_handler(sample_turn_off_action, context)
