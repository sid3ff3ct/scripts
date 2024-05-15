#!/usr/bin/python3
#
# This tool was simply written to convert the gnmap output from Nmap
# and present it in a nice table for command line.
# 
# This table can then be used to greb for specific content,
# sort, parse, etc.
# 
# Original Author: Alton Johnson
# Author: Daniel Brown
# Updated: 05/15/2024 (Modified to use tabulate with borders and separators)
# 

import re
from sys import argv


class colors:
    lightblue = "\033[1;36m"  # Removed non-breaking space
    blue = "\033[1;34m"
    normal = "\033[0;00m"
    red = "\033[1;31m"
    white = "\033[1;37m"
    green = "\033[1;32m"


try:
    import tabulate
except Exception:
    print(colors.red + " Error: The 'tabulate' python module isn't installed.")
    print(" Download tabulate and then run the script again. You can install it using 'pip install tabulate'.")
    exit()

banner = "\n " + "-" * 72 + "\n " + colors.white + " nmapparse 2.0 - Nmap Output Parser, Daniel Brown\n " + colors.normal + "-" * 72 + "\n "

def help():
    print(banner)
    print(" Usage: %s results.gnmap" % argv[0])
    print("\n Note: This script must point to a grepable output file from nmap to work properly.\n")
    exit()


def start(argv):
    table = []  # Create an empty list to store data
    if len(argv) == 0:
        help()
    contents = sorted(open(argv[0]).read().split('\n'))
    data = []

    for item in contents:
        ip_addr = item[item.find(":")+2:item.find("(")-1]
        info = re.findall("(?<=Ports: )(.*?)(?=Ignored)", item)
        if len(info) == 0:
            info = re.findall("(?<=Ports: )(.*?)(?=Seq Index)", item)
        if len(info) == 0:
            info = re.findall("(?<=Ports: )(.*?)(?=$)", item)
        if len(info) != 0:
            for i in info:
                result = i.split(',')
                for x in result:
                    port = re.findall("([0-9]+/open/.*?)/", x)
                    if "[]" in str(port):
                        continue
                    port = port[0].replace("/open", "")
                    service = re.findall("(?<=//)(.*?)(?=/)", x)[0]
                    version = x.split("/")[-2]
                    if len(version) > 40:
                        version = version[:40]
                    if len(version) == 0:
                        version = "-"
                    table.append([ip_addr, port, service, version])

    def print_table_with_border(table):
        # Generate the table using tabulate
        formatted_table = tabulate.tabulate(table, headers=["IP Address", "Port", "Service", "Version"], tablefmt="grid")

        # Define border characters (grid tablefmt already adds borders)

        # Print the formatted table
        print(formatted_table)

    print_table_with_border(table)


try:
    start(argv[1:])
except Exception as err:
    print(err)
