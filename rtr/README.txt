TO COMPILE THE DUMMY RTR
========================

* Patch lispd_lib.c with lispd_lib.patch to enable support of the RTR-related messages. 
  
* Patch lispd_nat_lib.c with lispd_nat_lib_RTR.patch to allow RTR to use static functions.

* Apply the proper values of the DEFINEs in rtr_external.h:

   -KEY = The key the MN is using to authenticate with the Map Server 
          (The RTR serves as a Map Server for the Info Messages)
   -KEY_TYPE = The type of the above key  
               (0 in any case. No other key type supported yet)
   -PEER_ADD = RLOC address of the peer.
               The RTR does not have support for send Map Requests, 
               so the RLOC of the peer EID is hardcoded.
   -RTR_TEST_RLOC = The address of the RTR.
   -RTR_TEST_RLOC_AFI = The AFI of the RTR (AF_INET for IPv4)


* Please note that the RTR does not implement support for replying to RLOC probes. 
  Deactivate where corresponds (most probably in the xTR of the peer) the RLOC probes to the RTR.



TO COMPILE THE MN WITH SUPPORT FOR THE DUMMY RTR
================================================

* Patch lispd_nat_lib.c with lispd_nat_lib_MN.patch,
  to hardcoded use of RTR instead of MS for NAT related stuff.

* Apply the proper values of the DEFINEs in lispd_nat_lib.c:

   -RTR_TEST_RLOC = The address of the RTR.
   -RTR_TEST_RLOC_AFI = The AFI of the RTR (AF_INET for IPv4)

