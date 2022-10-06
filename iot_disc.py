import sys
import os
import pandas as pd
import numpy as np
from mac_vendor_lookup import MacLookup
from requests_html import HTMLSession
from googlesearch import search
import webbrowser

# Program is dependent on tshark; otherwise argv should be a csv file
def main(argv):
    f = open(argv[0])
    filename, ext = os.path.splitext(argv[0])
    ext = ext.lower()
    if ext == ".pcap":
        os.system("tshark -r %s -T fields -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e _ws.col.Length -E header=y -E separator=, -E occurrence=f > %s.csv" %
                  (argv[0], filename))
        f = open(filename + ".csv")
    cols = {}
    data = pd.read_csv(f)
    for i, col in enumerate(data):
        if "_" in col:
            col = col[8:]
        cols[col.lower()] = i
    print(cols)
    zigbee_detected = False
    potential_iot_devs = set()
    for row in data.iterrows():
        # row[1] is the object data for a row of a panda; the 2D refrence is the specific column in the given row corresponding to the data at that col
        data_row = row[1]
        if data_row[cols["protocol"]] == "ZigBee" or zigbee_detected:
            if "IEEE" in data_row[cols["protocol"]] and zigbee_detected:
                src = data_row[cols["source"]]
                dst = data_row[cols["destination"]]
                if is_mac(src):
                    s = len(potential_iot_devs)
                    potential_iot_devs.add(src)
                    if s < len(potential_iot_devs):
                        print("Potential IoT device found!")
                if is_mac(dst):
                    s = len(potential_iot_devs)
                    potential_iot_devs.add(dst)
                    if s < len(potential_iot_devs):
                        print("Potential IoT device found!")
            elif "0x0000" == str(data_row[cols["source"]]):
                rtr = "Router"
                rtr += ": " + \
                    str(data_row[cols["destination"]]) if "0x" in str(
                        data_row[cols["destination"]]) else "s"
                print(
                    "ZigBee Coordinator pinging ZigBee %s on network. Searching for ZEDs..." % rtr)
            zigbee_detected = True
        elif data_row[cols["protocol"]] != "ZigBee":
            zigbee_detected = False

    mans = find_manufacturers(potential_iot_devs)
    #webscraping part is still needs to be completed but is outside of the scope of the program
    base_cve_url = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="
    urls = []
    for man in mans:
        cve = base_cve_url + "+".join(man.split(" ")) + "iot+zigbee"
        urls.append(cve)
    f = open("demo.html", "w")
    f.write(to_html(mans,urls))
    f.close()
    webbrowser.open("demo.html")
    
        

#not currently working
def get_man_picture(query):
    session = HTMLSession()
    url = "https://www.google.com/search?q=" + "+".join(query.split(" ")) + "&oq=em&aqs=chrome.0.69i59l3j69i57j69i61j69i60l2.955j0j15&sourceid=chrome&ie=UTF-8"
    r = session.get(url)
    r.html.render()
    first_image = r.html.find('.rg_ic.rg_i', first=True)
    link = first_image.attr['src']
    return link

def find_manufacturers(potential_iot_devs):
    companies = []
    for mac in potential_iot_devs:
        man = MacLookup().lookup(mac[:17])
        print("IoT device MAC address " +
              str(mac[:17]) + " | Manufacture: " + man)
        companies.append(man)
    return companies


def is_mac(potential_mac):
    lst = str(potential_mac).split(":")
    if len(lst) >= 6:
        for x in lst:
            if not is_int(x):
                return False
        return True
    else:
        return False


def to_html (comp, url):
    c='<h1>Devices by Manufacture</h1>'
    c1='<div class="company-photo"><img src="ember.png" alt="picture of the company"></div><div class="center"> <h2> %s </h2> <h3>Potential IoT devices: Q59 Dual Band, Q51 802.15.4 PANanalyzer </h3> <a href="%s">CVEs</a> </div>' % (comp[0], url[0])
    c2='<div class="company-photo"><img src="exegin.png" alt="picture of the company"></div><div class="center"> <h2> %s </h2> <h3>Potential IoT devices: EM351 </h3> <a href="%s">CVEs</a> </div>' % (comp[1], url[1])
    temp = open("subst.txt").read()
    temp += c
    temp += c1 
    temp += c2
    temp += "</body></html>"
    return temp


def is_int(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    main(sys.argv[1:])
