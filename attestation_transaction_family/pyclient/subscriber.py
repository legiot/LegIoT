import paho.mqtt.client as mqtt  # This is the Subscriber#hostname
import json
broker = "broker"  # port
port = 1883  # time to live
timelive = 60


def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    client.subscribe("trustmngt/query")

def on_message(client, userdata, msg):
       # print(msg.payload.decode())
        m_decode = str(msg.payload.decode("utf-8", "ignore"))
        m_in = json.loads(m_decode)  # decode json data
        Batch_list = m_in["batch_list"]
        Batch_ID = m_in["batch_id"]
        Dev_ID = m_in["client_id"]
        print(Batch_list)


client = mqtt.Client()
client.connect(broker, port, timelive)
client.on_connect = on_connect
client.on_message = on_message
client.loop_forever()