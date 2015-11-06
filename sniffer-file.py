#!/usr/bin/env python
# The previous line ensures that this script is run under the context
# of the Python interpreter. Next, import the Scapy functions:
from scapy.all import *
import threading
import time
import socket #THE MAIN ONE FOR NETWORK :D
import os #stats of file
import urllib2
import urllib
import subprocess

#Just change this 

map_location="muriqanIn"
#map_location="muriqanOut"

reboot_time = 3600 #in seconds

port = 80
host = "http://52.26.93.166"
filename = "/core/initProbe.php?count="
f_location = "&location="
sendClients = "/core/storeclients.php"

#c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#c.connect((host, port))

#fileObj = c.makefile('r', 0)


# Define the interface name that we will be sniffing from, you can
# change this if needed.
interface = "wlan1mon"

# Next, declare a Python list to keep track of client MAC addresses
# that we have already seen so we only print the address once per client.
observedclients = []

def countclients():
    while(True):
        try:
            #print("[*]"+str(len(observedclients)))
            #fileObj.write("GET " + filename+str(len(observedclients)) + " HTTP/1.0\r\n\n\n")
            #response = urllib2.urlopen(host+filename+str(len(observedclients))+f_location+map_location)
     #print('\n'+host+filename+str(len(observedclients))+f_location+'Epoka'+'\n')
            print "count: "+str(len(observedclients))
	except:
            print "Server problem, could not send the count\n"
        time.sleep(30)

def sendclients():
    global observedclients
    while(True):
        try:
            if len(observedclients) > 0:
                #print "Sending"
                copyclients = observedclients[:]
                observedclients = []

                #continue with copyclients
                values = { 'clients': copyclients, 'location':  map_location}

		fl = open('clients.txt', 'a')
		for clnt in copyclients:
			fl.write(str(clnt)+" "+str(time.strftime('%Y-%m-%d %H:%M:%s'))+"\n")
		fl.write("\n")
		fl.close()
		
                #data = urllib.urlencode(values)
                #req = urllib2.Request(host+sendClients, data)
                #response = urllib2.urlopen(req)
                #result = response.read()
                #print result
                #print "\n\n"
        except:
            print "Nothing to send\n"
            
        time.sleep(30) #sleep 30 seconds -> for 5 minutes (300)

def rebooter():
    global reboot_time

    time.sleep(reboot_time) #sleep for this time

    #after sleeping reboot the system
    subprocess.call("sudo reboot", shell=True)

# The sniffmgmt() function is called each time Scapy receives a packet
# (we'll tell Scapy to use this function below with the sniff() function).
# The packet that was sniffed is passed as the function argument, "p".
def sniffmgmt(p):

    # Define our tuple (an immutable list) of the 3 management frame
    # subtypes sent exclusively by clients. I got this list from Wireshark.
    stamgmtstypes = (0, 2, 4)

    # Make sure the packet has the Scapy Dot11 layer present
    if p.haslayer(Dot11):

        # Check to make sure this is a management frame (type=0) and that
        # the subtype is one of our management frame subtypes indicating a
        # a wireless client
        if p.type == 0 and p.subtype in stamgmtstypes:

            # We only want to print the MAC address of the client if it
            # hasn't already been observed. Check our list and if the
            # client address isn't present, print the address and then add
            # it to our list.
            if p.addr2 not in observedclients:
                print p.addr2
                observedclients.append(p.addr2)

#run as thread the countclients
t = threading.Thread(target=countclients)
t.start()

sc = threading.Thread(target=sendclients)
sc.start()

reb = threading.Thread(target=rebooter)
reb.start()

# With the sniffmgmt() function complete, we can invoke the Scapy sniff()
# function, pointing to the monitor mode interface, and telling Scapy to call
# the sniffmgmt() function for each packet received. Easy!
sniff(iface=interface, prn=sniffmgmt)

"""
    From here, lots of opportunities become available.
    For example, we could disconnect each client from the
    network by adding the following line after the print statement:
    
    sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())
"""

