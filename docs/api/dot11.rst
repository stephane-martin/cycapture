=====================
IEEE 802.11 and stuff
=====================

.. contents::
   :local:
   :backlinks: top

Base IEEE 802.11
================
.. autoclass:: cycapture.libtins._tins.Dot11

IEEE 802.11 data frames
=======================
.. autoclass:: cycapture.libtins._tins.Dot11Data
.. autoclass:: cycapture.libtins._tins.Dot11QoSData

IEEE 802.11 management frames
=============================
.. autoclass:: cycapture.libtins._tins.Dot11ManagementFrame

Assoc
-----
.. autoclass:: cycapture.libtins._tins.Dot11Disassoc
.. autoclass:: cycapture.libtins._tins.Dot11AssocRequest
.. autoclass:: cycapture.libtins._tins.Dot11AssocResponse
.. autoclass:: cycapture.libtins._tins.Dot11ReAssocRequest
.. autoclass:: cycapture.libtins._tins.Dot11ReAssocResponse

Auth
----
.. autoclass:: cycapture.libtins._tins.Dot11Authentication
.. autoclass:: cycapture.libtins._tins.Dot11Deauthentication

Beacon
------
.. autoclass:: cycapture.libtins._tins.Dot11Beacon

Probes
------
.. autoclass:: cycapture.libtins._tins.Dot11ProbeRequest
.. autoclass:: cycapture.libtins._tins.Dot11ProbeResponse

IEEE 802.11 control frames
==========================
.. autoclass:: cycapture.libtins._tins.Dot11Control
.. autoclass:: cycapture.libtins._tins.Dot11RTS
.. autoclass:: cycapture.libtins._tins.Dot11PSPoll
.. autoclass:: cycapture.libtins._tins.Dot11CFEnd
.. autoclass:: cycapture.libtins._tins.Dot11EndCFAck
.. autoclass:: cycapture.libtins._tins.Dot11Ack
.. autoclass:: cycapture.libtins._tins.Dot11BlockAckRequest
.. autoclass:: cycapture.libtins._tins.Dot11BlockAck

Helpers
=======
Capabilities
------------
.. autoclass:: cycapture.libtins._tins.Capabilities

RSN information
---------------
.. autoclass:: cycapture.libtins._tins.RSNInformation


Named tuples
------------
.. autoclass:: cycapture.libtins._tins.fh_params
   :no-members:
.. autoclass:: cycapture.libtins._tins.cf_params
   :no-members:
.. autoclass:: cycapture.libtins._tins.dfs_params
   :no-members:
.. autoclass:: cycapture.libtins._tins.country_params
   :no-members:
.. autoclass:: cycapture.libtins._tins.fh_pattern
   :no-members:
.. autoclass:: cycapture.libtins._tins.channel_switch_t
   :no-members:
.. autoclass:: cycapture.libtins._tins.quiet_t
   :no-members:
.. autoclass:: cycapture.libtins._tins.bss_load_t
   :no-members:
.. autoclass:: cycapture.libtins._tins.tim_t
   :no-members:
.. autoclass:: cycapture.libtins._tins.vendor_specific_t
   :no-members:

