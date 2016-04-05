================
libpcap bindings
================

.. contents::
   :local:
   :backlinks: top

Sniffers
========
Blocking Sniffer
----------------
.. autoclass:: cycapture.libpcap._pcap.BlockingSniffer

Non-blocking sniffer
--------------------
.. autoclass:: cycapture.libpcap._pcap.NonBlockingSniffer

Packet writers
==============
.. autoclass:: cycapture.libpcap._pcap.PacketWriter
.. autoclass:: cycapture.libpcap._pcap.NonBlockingPacketWriter

Offline filter
==============
.. autoclass:: cycapture.libpcap._pcap.OfflineFilter

Utils
=====
.. autoclass:: cycapture.libpcap._pcap.SniffingIterator
.. autoclass:: cycapture.libpcap._pcap.BaseSniffer
.. autofunction:: cycapture.libpcap._pcap.lookupdev
.. autofunction:: cycapture.libpcap._pcap.datalink_to_description
.. autofunction:: cycapture.libpcap._pcap.lookupnet
.. autoattribute:: cycapture.libpcap._pcap.libpcap_version
   :annotation: = "version of the wrapped libpcap library"
