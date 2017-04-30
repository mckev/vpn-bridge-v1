# vpn-bridge-v1
VPN Server and Client written in C.


## Features
  - VPN Client is implemented as layer 2 bridge on a Raspberry Pi.
  - VPN Server is hosted on a Linux server.


## How to install
```
 1. Plug-in Apple USB Ethernet Adapter MC704ZM/A into Raspberry Pi.
       $ sudo tail -f /var/log/messages
Apr  5 21:19:35 raspberrypi kernel: [ 1278.378158] usb 1-1.3: new high-speed USB device number 4 using dwc_otg
Apr  5 21:19:35 raspberrypi kernel: [ 1278.495386] usb 1-1.3: New USB device found, idVendor=05ac, idProduct=1402
Apr  5 21:19:35 raspberrypi kernel: [ 1278.495424] usb 1-1.3: New USB device strings: Mfr=1, Product=2, SerialNumber=3
Apr  5 21:19:35 raspberrypi kernel: [ 1278.495444] usb 1-1.3: Product: Apple USB Ethernet Adapter
Apr  5 21:19:35 raspberrypi kernel: [ 1278.495461] usb 1-1.3: Manufacturer: Apple Inc.
Apr  5 21:19:35 raspberrypi kernel: [ 1278.495478] usb 1-1.3: SerialNumber: 279130
Apr  5 21:19:36 raspberrypi kernel: [ 1278.890956] asix 1-1.3:1.0 eth1: register 'asix' at usb-bcm2708_usb-1.3, ASIX AX88772 USB 2.0 Ethernet, f4:f9:51:f2:89:38
Apr  5 21:19:36 raspberrypi kernel: [ 1278.892990] usbcore: registered new interface driver asix

       $ /sbin/ifconfig
eth0      Link encap:Ethernet  HWaddr b8:27:eb:cd:b7:d8
          inet addr:192.168.10.129  Bcast:192.168.10.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:417 errors:0 dropped:0 overruns:0 frame:0
          TX packets:346 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:35493 (34.6 KiB)  TX bytes:42384 (41.3 KiB)
eth1      Link encap:Ethernet  HWaddr f4:f9:51:f2:89:38
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)




 2. Simplest bridge:
       $ sudo apt-get install bridge-utils
       $ sudo brctl addbr br0
       $ sudo brctl addif br0 eth0
       $ sudo brctl addif br0 eth1
       $ sudo ip link set br0 up					--> optional




 3. Auto boot:
       $ sudo vi /etc/network/interfaces
iface eth0 inet manual

iface eth1 inet manual

auto br0
iface br0 inet dhcp
   bridge_ports eth0 eth1
   bridge_stp off
   bridge_maxwait 5


       $ sudo service networking restart
[....] Running /etc/init.d/networking restart is deprecated because it may not r[warnble some interfaces ... (warning).
[....] Reconfiguring network interfaces...
Waiting for br0 to get ready (MAXWAIT is 5 seconds).
Internet Systems Consortium DHCP Client 4.2.2
Copyright 2004-2011 Internet Systems Consortium.
All rights reserved.
For info, please visit https://www.isc.org/software/dhcp/
Listening on LPF/br0/b8:27:eb:cd:b7:d8
Sending on   LPF/br0/b8:27:eb:cd:b7:d8
Sending on   Socket/fallback
DHCPDISCOVER on br0 to 255.255.255.255 port 67 interval 8
DHCPREQUEST on br0 to 255.255.255.255 port 67
DHCPOFFER from 192.168.10.1
DHCPACK from 192.168.10.1
bound to 192.168.10.129 -- renewal in 82508 seconds.
done.


       $ /sbin/ifconfig
br0       Link encap:Ethernet  HWaddr b8:27:eb:cd:b7:d8
          inet addr:192.168.10.129  Bcast:192.168.10.255  Mask:255.255.255.0
          inet6 addr: fe80::ba27:ebff:fecd:b7d8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:215 errors:0 dropped:0 overruns:0 frame:0
          TX packets:31 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:28400 (27.7 KiB)  TX bytes:5918 (5.7 KiB)

eth0      Link encap:Ethernet  HWaddr b8:27:eb:cd:b7:d8
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1258 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1403 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:247682 (241.8 KiB)  TX bytes:242249 (236.5 KiB)

eth1      Link encap:Ethernet  HWaddr f4:f9:51:f2:89:38
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1247 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:173968 (169.8 KiB)  TX bytes:205783 (200.9 KiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)


       $ brctl show
bridge name     bridge id               STP enabled     interfaces
br0             8000.b827ebcdb7d8       no              eth0
                                                        eth1
```
