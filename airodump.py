import pcap
import sys

TAG_SSID = 0
TAG_CHANNEL = 3
PASS = 10000

class Radiotap:

    def __init__(self, string):
        self.version = string[0]
        self.pad = string[1]
        self.len = string[2:4]
        self.present = string[4:8]

    def skip(self, string):
        radio_len = int.from_bytes(self.len, byteorder='little')
        return string[radio_len:]


class Beacon:

    def __init__(self, string):
        self.frame_control = string[:2]
        self.duration_id = string[2:4]
        self.DA = string[4:10]
        self.SA = string[10:16]
        self.BSS_ID = string[16:22]
        self.sequence = string[22:24]

        # frame body
        self.time_stamp = string[24:32]
        self.beacon_interval = string[32:34]
        self.capacity_information = string[34:36]
        self.option = string[36:]

    def check(self):
        if self.frame_control == b'\x80\x00':
            return True
        else:
            return False

    def check_tag(self, string):
        if string[0] == 0:
            return TAG_SSID
        elif string[0] == 3:
            return TAG_CHANNEL
        else:
            return PASS

    def skip(self, string):
        tag_length = string[1]
        return string[2 + tag_length:]

    def print_ssid(self, string):
        length = string[1]
        ssid_string = ''
        for i in range(length):
            ssid_string += chr(string[2+i])
        print('ssid: ', ssid_string)

    def print_channer(self, string):
        print('channer: ', string[2])

    def print_beacon(self):
        print('---------------------------')
        print('BSSID:', ':'.join('{:x}'.format(B) for B in self.BSS_ID))
        tag_string = self.option
        while tag_string:
            tag_sig = self.check_tag(tag_string)
            if (tag_sig == TAG_SSID):
                self.print_ssid(tag_string)
            elif (tag_sig == TAG_CHANNEL):
                self.print_channer(tag_string)

            tag_string = self.skip(tag_string)
        print()


######### main #########

if len(sys.argv) != 2:
    print("python airodump.py {network interface name}")
    exit()

try:
    i_name = sys.argv[1]
    sniffer = pcap.pcap(name=i_name, promisc=True, immediate=True, timeout_ms=50)

    for ts, buf in sniffer:
        radiotap = Radiotap(buf)
        radio_string = radiotap.skip(buf)
        beacon = Beacon(radio_string)
        if(not beacon.check()): continue
        beacon.print_beacon()
except Exception as e:
    sys.exit(e)