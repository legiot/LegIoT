# simulator device 1 for mqtt message publishing
import paho.mqtt.client as paho
import time
import random  # hostname

broker = "broker"  # port
port = 1883


def on_publish(client, userdata, result):
    print("Device 1 : Data published.")
    pass

client = paho.Client("admin")


client.on_publish = on_publish
client.connect(broker, port)
for i in range(20):
    d = random.randint(1, 5)
    # telemetry to send
    message = "Device 1 : Data " + str(i)
    time.sleep(d)
    # publish message
    ret = client.publish("/data", message)
print("Stopped...")