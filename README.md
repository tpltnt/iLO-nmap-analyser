# iLO-nmap-analyser
This is a simple Python (3) script to find HPE iLO issues from nmap scans.

# usage
1. install nmap
2. get iLO scanning script from [here](https://github.com/nmap/nmap/pull/1082)
3. run `nmap --script ./ilo-info.nse -oX iLO_scan.xml IP_RANGE`


# references
* [nmap](https://nmap.org)
* [Subverting your server through its BMC: the HPE iLO4 case](https://airbus-seclab.github.io/ilo/SSTIC2018-Article-subverting_your_server_through_its_bmc_the_hpe_ilo4_case-gazet_perigaud_czarny.pdf)
