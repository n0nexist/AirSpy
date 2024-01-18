"""
github.com/n0nexist/AirSpy
"""
from scapy.all import *
from threading import Thread
from rich.console import Console
from rich.table import Table
from rich.color import Color
from rich.style import Style
from rich.align import Align
import signal
from manuf import MacParser
import argparse
import time
import subprocess

_5ghz = False

parser = argparse.ArgumentParser(
                    prog='AirSpy',
                    description='The ultimate python Wi-Fi scanner (2.4GHz and 5Ghz) ',
                    epilog='github.com/n0nexist/AirSpy')

parser.add_argument('-fg', '--fghz', help="Use 5Ghz channels instead of 2.4Ghz", action=argparse.BooleanOptionalAction)
parser.add_argument('-i', '--interface', help="The wifi card to use")
parser.add_argument('-c', '--channel', help="Use only a specified channel", type=int)

args = parser.parse_args()

inter = args.interface
_5ghz = (args.fghz == True)
channel = args.channel

if os.getuid()!=0:
    print("You need root permissions to use AirSpy")
    exit(2)

if _5ghz and (channel != None):
    print("You can't specify both 5Ghz and a single channel")
    exit(3)

def getRGB(r,g,b):
    return Style(color=Color.from_rgb(r,g,b))

p = MacParser()
table = Table(title=f"AirSpy | {'5Ghz' if _5ghz else '2.4Ghz'}")
console = Console()

table.add_column("SSID", justify="right", style=getRGB(105, 245, 135), no_wrap=True)
table.add_column("BSSID", justify="right", style=getRGB(46, 184, 170), no_wrap=True)
table.add_column("BRAND", justify="center", style=getRGB(161, 240, 24), no_wrap=True)
table.add_column("ENCR", justify="right", style="white", no_wrap=True)
table.add_column("RSSI", justify="right", style="white", no_wrap=True)
table.add_column("CHANNEL", justify="right", style="magenta", no_wrap=True)

original_title = table.title

clients_table = Table(title="\n\nPROBES")

clients_table.add_column("FROM", justify="right", style=getRGB(105, 245, 135), no_wrap=True)
clients_table.add_column("TO", justify="right", style=getRGB(46, 184, 170), no_wrap=True)
clients_table.add_column("BRAND FROM", justify="center", style=getRGB(161, 240, 24), no_wrap=True)
clients_table.add_column("BRAND TO", justify="center", style=getRGB(161, 240, 24), no_wrap=True)
clients_table.add_column("RSSI", justify="right", style="white", no_wrap=True)
clients_table.add_column("CHANNEL", justify="right", style="magenta", no_wrap=True)

def truncateString(input_string, max_length=21):
    if len(input_string) > max_length and "None" not in input_string:
        return input_string[:max_length-1] + "."
    else:
        return input_string

nonestr = f"[{getRGB(112, 107, 107)}]None[/{getRGB(112, 107, 107)}]"

def getVendor(mac):

    if str(mac) == None:
        return nonestr

    temp = p.get_manuf_long(mac)
    if temp != None:
        return temp


    return str(p.get_manuf(mac)).replace("None",nonestr)

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

current_channel = 0

def hopChannels(interf):
    global current_channel

    if channel==None:

        channels = get_channels(interf)

        while True:
            for x in channels:
                os.popen(f"iwconfig {interf} channel {x}").read()
                current_channel = x
                table.title = original_title+f" | CHANNEL={x}"
                time.sleep(0.03)
    
    else:
        current_channel = channel
        os.popen(f"iwconfig {interf} channel {channel}").read()
        table.title = original_title+f" | CHANNEL={channel}"

        return

def quitThread():
    input()
    print("\033[0;0m")
    os.kill(os.getpid(),signal.SIGKILL)

found_bssids = []
found_clients = []

def packetHandler(pkt):
    global table
    global found_bssids
    global found_clients
    global clients_table
    global current_channel

    try:

        if pkt.haslayer(Dot11Beacon):

            wifi_mac = pkt.addr2
            wifi_dest = pkt.addr3

            if wifi_mac in found_bssids:
                return

            found_bssids.append(wifi_mac)

            if wifi_mac == wifi_dest:

                wifi_name = pkt.info.decode()

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

                vendor = truncateString(getVendor(wifi_mac))
            
                table.add_row(wifi_name,wifi_mac,vendor,enctype,str(rssi),channel)

        elif pkt.haslayer(Dot11):

            _from = str(pkt.addr2)
            _dest = str(pkt.addr3)

            if _from == _dest:
                return
            
            if _from+_dest in found_clients:
                return

            found_clients.append(_from+_dest)

            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "unknown"

            clients_table.add_row(_from,_dest,truncateString(getVendor(_from)),truncateString(getVendor(_dest)),f"{rssi}",f"{current_channel}")
    
    except Exception as e:
        f = open("errors.txt","a")
        f.write(f"\n{e}\n")
        f.close()


def printTable():
    global table
    global clients_table
    while True:
        os.system("clear")
        console.print(Align.center(table, vertical="middle"))
        console.print(Align.center(clients_table, vertical="middle"))
        time.sleep(0.8)

Thread(target=hopChannels,args=(inter,)).start()
Thread(target=printTable).start()
Thread(target=quitThread).start()

sniff(prn=packetHandler,iface=inter)
