"""
github.com/n0nexist/AirSpy
"""
from scapy.all import *
from threading import Thread
from rich.console import Console
from rich.table import Table
from rich.color import Color
from rich.style import Style
import signal
from manuf import MacParser
import sys
import time
import subprocess

_5ghz = False

try:
    _5ghz = sys.argv[2].lower() == "5ghz"
except:
    pass

try:
    inter = sys.argv[1]
except:
    print("The first argument must be your wifi interface's name")
    exit(1)

if os.getuid()!=0:
    print("You need root permissions to use AirSpy")
    exit(2)

def getRGB(r,g,b):
    return Style(color=Color.from_rgb(r,g,b))

p = MacParser()
table = Table(title=f"AirSpy | {'5Ghz' if _5ghz else '2.4Ghz'}")
console = Console()

table.add_column("SSID", justify="right", style=getRGB(105, 245, 135), no_wrap=True)
table.add_column("BSSID", justify="right", style=getRGB(46, 184, 170), no_wrap=True)
table.add_column("BRAND", justify="center", style=getRGB(130, 120, 91), no_wrap=True)
table.add_column("ENCR", justify="right", style="white", no_wrap=True)
table.add_column("RSSI", justify="right", style="white", no_wrap=True)
table.add_column("CHANNEL", justify="right", style="magenta", no_wrap=True)

original_title = table.title

def getVendor(mac):
    temp = p.get_manuf_long(mac)
    if temp != None:
        return temp
    
    return str(p.get_manuf(mac)).replace("None",f"[{getRGB(112, 107, 107)}]None[/{getRGB(112, 107, 107)}]")

def get_channels(interface):
    channels = []

    if not _5ghz:
        channel_list = range(1,20)
    else:
        channel_list = range(36,165)

    for x in channel_list:

        process = subprocess.Popen(f"iwconfig {interface} channel {x}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if not stderr:
            channels.append(x)

    return channels

def hopChannels(interf):

    channels = get_channels(interf)

    while True:
        for x in channels:
            os.popen(f"iwconfig {interf} channel {x}").read()
            table.title = original_title+f" | CHANNEL={x}"
            time.sleep(0.03)


def quitThread():
    input()
    print("\033[0;0m")
    os.kill(os.getpid(),signal.SIGKILL)

found_bssids = []

def packetHandler(pkt):
    global table
    global found_bssids

    if pkt.haslayer(Dot11Beacon):

        wifi_mac = pkt.addr2

        if wifi_mac in found_bssids:
            return

        found_bssids.append(wifi_mac)

        if wifi_mac == pkt.addr3:

            wifi_name = pkt.info.decode()

            sec_info = pkt[Dot11Beacon].getlayer(Dot11Beacon).cap
            try:
                netstats = pkt[Dot11Beacon].network_stats()
                channel  = netstats['channel']
                enctype  = str('/'.join(netstats['crypto']))
            except:
                channel = "unknown"
                enctype = "unknown"

            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "unknown"

            if enctype=="OPN":
                enctype = f"[{getRGB(156, 58, 58)} on white]OPEN[/{getRGB(156, 58, 58)} on white]"
            elif enctype=="WEP":
                enctype = f"[bold yellow on red]WEP[/bold yellow on red]"
            else:
                enctype = f"[{getRGB(112, 107, 107)}]{enctype}[/{getRGB(112, 107, 107)}]"

            channel = str(channel)
            if len(channel)==1:
                channel+=" "

            vendor = getVendor(wifi_mac)
            
            table.add_row(wifi_name,wifi_mac,vendor,enctype,str(rssi),channel)

        else:
            pass
            
            #print(wifi_mac, pkt.addr3)

def printTable():
    global table
    while True:
        os.system("clear")
        console.print(table)
        time.sleep(0.3)

Thread(target=hopChannels,args=(inter,)).start()
Thread(target=printTable).start()
Thread(target=quitThread).start()

sniff(prn=packetHandler,iface=inter)