#!/usr/bin/env /usr/bin/python3.4

# Power Socket Subscriber
#
# This program subscribes to an MQTT topic and when messages are received, it passes on a message,
# using raspberry strogonanoff (https://github.com/dmcg/raspberry-strogonanoff), to turn a Maplin
# power socket on or off. 

import sys
import os
import socket
import ssl
import json
import time
import logging
import signal
import argparse
import paho.mqtt.client as paho
from subprocess import Popen, PIPE

# Set up logging.
logging.basicConfig(format='%(asctime)s %(levelname)s %(funcName)s:%(lineno)d %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# The MQTT client needs to be global so the signal handler can see it (Ctrl-C).
mqtt_client = None

# Where configuration is stored
switch_config = None

# Invoke raspberry strogonanoff
def switch_power_socket(sender_path, channel, button, action):
    """Does the grunt work of calling strogonanoff_sender.py
    Builds an array of strings to pass to Popen. Currently needs NOPASSWD sudo
    access to interact with /dev/mem.
    """

    # TODO Remove dependence on sleep, we should be able to wait for a response from strogonanoff
    sleep_time = 2
    loops = 2

    cmd = ["/usr/bin/sudo", sender_path,
           "-c", str(channel), "-b", str(button), action]
    try:
        for _ in range(loops):
            logging.debug("Setting channel=%s button=%s to action=%s" %
                          (str(channel), str(button), action))
            logging.debug("running cmd=%s", cmd)
            _ = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            logging.debug("Sleeping %d" % sleep_time)
            time.sleep(sleep_time)
    except Exception:
        logging.exception("Strogonanoff command failed: %s", ' '.join(cmd))


def connect(mqtt_broker_host, mqtt_broker_port, ca_certs_file, client_cert_file, client_key_file, topic_base, strogonanoff_path):

    # Create our own SSLContext object so we have full control.  Using helper methods seems to preclude
    # using a separate certificate authorities file and client certificate file.
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # We only want to permit TLS v1.2 or greater
    client_context.options |= ssl.OP_NO_TLSv1
    client_context.options |= ssl.OP_NO_TLSv1_1

    # This won't work unless the first certificate in client_cert_file corresponds to the private key in client_key_file
    logger.info("Loading TLS certs and keys.  CA file: \"%s\"; Cert file: \"%s\"; Key file: \"%s\"",
                ca_certs_file, client_cert_file, client_key_file)
    client_context.load_cert_chain(client_cert_file, client_key_file)
    client_context.load_verify_locations(ca_certs_file)

    # Create an MQTT client object and configure it with the SSL Context we've created
    client_name = "Remote Control Power Socket Subscriber Client: {}:{}".format(socket.gethostname(), os.getpid())
    logger.info("Create MQTT client %s", client_name)
    client = paho.Client(client_name)
    client.user_data_set(strogonanoff_path)
    client.tls_set_context(client_context)

    logger.info("Connecting to MQTT broker %s:%s", mqtt_broker_host, mqtt_broker_port)
    client.connect(mqtt_broker_host, mqtt_broker_port)

    # Hook up the different event handlers
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_subscribe = on_subscribe

    topic_action = topic_base + "/action"
    topic_config = topic_base + "/config"

    client.message_callback_add(topic_action, on_action)
    client.message_callback_add(topic_config, on_config)

    client.subscribe(topic_base + "/#", 0)
    
    return client

# When a new configuration is received
def on_config(client, userdata, message):

    global switch_config

    logger.debug("Received (topic={}, qos={}, retain={}): {}".format(message.topic, message.qos, message.retain, message.payload))

    try:
        switch_config = json.loads(message.payload.decode("utf-8"))
    except:
        logging.exception("Failed to parse json. message=%s" % message.payload)
        return False

    logging.debug("Configuration loaded in to socketConfig successfully")

def on_action(client, userdata, message):
    """ Callback invoked when a message is received on the "action" topic.

    As long as the JSON is ok, this should cause a socket to be switched on or off"""
    
    logger.debug("Received (topic={}, qos={}, retain={}): {}".format(message.topic, message.qos, message.retain, message.payload))

    # json_string = str(message.payload.decode("utf-8"))

    if switch_config is None:
        logging.debug("Switches are not configured yet, ignoring this request")
        return False

    try:
        data = json.loads(message.payload.decode("utf-8"))
    except:
        logging.debug("failed to parse json. message=%s" % message.payload)
        return False

    device_name = data.get('device')
    scene_name = data.get('scene')   
    action = data.get('action')
    source = "source not defined yet"
    # BUG This is not how you use userdata!  Instead sender_path will be a global
    # sender_path = userdata["strogonanoff_path"]

    # Only 'on' and 'off' are supported
    if action != "on" and action != "off":
        logging.debug("action (%s) is not valid" % action)
        return False

    if device_name in switch_config['devices']:
        channel = switch_config['devices'][device_name]['channel']
        button = switch_config['devices'][device_name]['button']

        logging.debug("switch=%s channel=%s button=%s action=%s source=%s" %
                      (device_name, channel, button, action, source))

        switch_power_socket(sender_path, channel, button, action)

    elif scene_name in switch_config['scenes']:
        logging.debug("Handling scene=%s" % scene_name)
        switch_list = switch_config['scenes'][scene_name]

        for switch in switch_list:

            channel = switch_config['devices'][switch]['channel']
            button = switch_config['devices'][switch]['button']

            logging.debug("switch=%s channel=%s button=%s action=%s source=%s scene=%s" %
                          (switch, channel, button, action, source, scene_name))
            switch_power_socket(sender_path, channel, button, action)
    else:
        # if it isn't in rooms or scenes it isn't valid, so return
        logging.debug("Either Device({}) or Scene({}) not found".format(device_name,scene_name))
        return False


# MQTT callback on successful subscribe
def on_subscribe(client, userdata, mid, granted_qos):
    logging.info("sub ack %s, granted QOS: %s", str(mid), granted_qos)
    # for t in topic_ack:
    #     # test subscription mid against those stored in array
    #     if t[1] == mid:
    #         t[2] = 1 #set acknowledged flag
    #         logging.info("subscription acknowledged "+t[0])


# MQTT callback when connected to the broker
def on_connect(client, userdata, flags, rc):
    logging.info("Connected to broker: userdata(%s), flags(%s), rc(%s)", userdata, flags, rc)
    client.connected_flag = True


# MQTT callback when disconnected from the broker
def on_disconnect(client, userdata, rc=0):
    logging.info("Disconnected result code %s %s", userdata, rc)
    client.loop_stop()


# Invoked on an interrupt signal (Ctrl-C)
def signal_handler(signal, frame):
    logger.info("Interrupt detected!  Terminating gracefully")
    logger.info("Disconnecting from the MQTT broker")
    mqtt_client.disconnect()

    logger.info("Stopping the MQTT client loop (forced)")
    mqtt_client.loop_stop(True)

if __name__ == "__main__":
    logger.info("Starting %s", __file__)

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="verbose output to console", action="store_true")
    parser.add_argument("-a", "--cafile", help="path to a file containing trusted CA certificates to enable encrypted "
                                               "certificate based communication.", default="ca-chain.cert.pem")
    parser.add_argument("-c", "--cert", help="client certificate for authentication, if required by server.",
                        default="HomeAutomationMQTTSubscriber.cert.pem")
    parser.add_argument("-k", "--key", help="client private key for authentication, if required by server",
                        default="HomeAutomationMQTTSubscriber.key.pem")
    parser.add_argument("-t", "--mqtttopic", help="mqtt topic to subscribe to.", default="homeautomation/power")
    parser.add_argument("-o", "--mqtthost", help="MQTT broker hostname.", default="wensum.ddns.net")
    parser.add_argument("-p", "--mqttport", help="MQTT network port to connect to.", default="8883")
    parser.add_argument("-s", "--strogonanoffpath", help="Full path to strogonanoff directory containing strogonanoff_sender.py", default="/home/andy/maplin/raspberry-strogonanoff/src/strogonanoff_sender.py")
    
    args = parser.parse_args()

    # Check strogonanoff Sender path
    if not os.path.isfile(args.strogonanoffpath):
        logger.error("Could not find strogonanoff_sender.py at %s", args.strogonanoffpath)
    else:    

        # BUG Making this global instead of using userdata, which isn't working currently
        global sender_path
        sender_path = args.strogonanoffpath

        # Connect to the MQTT broker
        mqtt_client = connect(args.mqtthost, int(args.mqttport), args.cafile, args.cert, args.key, args.mqtttopic, args.strogonanoffpath)

        # Register a Ctrl-C signal handler so we disconnect from MQTT broker and terminate gracefully
        signal.signal(signal.SIGINT, signal_handler)

        mqtt_client.loop_forever()

    logger.info("Terminated")
