
#!/usr/bin/env python3
"""
Analyse the nmap scan for iLO.
"""
import argparse
import xml.etree.ElementTree as ET


def extract_ilo_information(host):
    """
    Extract relevant information for the iLO evaluation.

    :param host: host element from nmaprun
    :type host: xml.etree.ElementTree.Element
    :returns: list of dict (may be empty)
    """
    # hosts need to be up
    if host.find('status').get('state') != "up":
        return []

    # hosts need to have ports
    p = host.find('ports')
    if not p:
        return []

    # ports need to be open
    OPEN = list(filter(lambda p: p.find('state').get('state') == "open",
                       p.findall('port')))
    if not OPEN:
        return []

    # the 'ilo-info' script needs to have been run
    ILO_INFO = []
    for p in OPEN:
        for s in p.findall('script'):
            info = {}
            info['host'] = h.find("address").get("addr")
            info['port'] = int(p.get("portid"))
            if "ilo-info" != s.get("id"):  # wrong script
                continue

            for e in s.findall('elem'):
                if e.get("key") == "ServerType":
                    info['ServerType'] = e.text
                if e.get("key") == "UUID":
                    info['UUID'] = e.text
                if e.get("key") == "cUUID":
                    info['cUUID'] = e.text
                if e.get("key") == "ILOType":
                    info['ILOType'] = e.text
                if e.get("key") == "ILOFirmware":
                    info['ILOFirmware'] = float(e.text)
                if e.get("key") == "SerialNo":
                    info['SerialNo'] = e.text
            ILO_INFO.append(info)
    return ILO_INFO


def detect_cve(host):
    """
    Try to detect potential issues and reference them by CVE.

    :param host: host (XML) node from nmap scan
    :type host: xml.etree.ElementTree.Element
    :returns: list of dict (may be empty, keys: cve, info)
    """
    vulns = []
    if host['ILOFirmware'] < 2.55 and '(iLO 4)' in host['ILOType']:
        data = {'cve': "CVE-2017-12542",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03769en_us"}
        vulns.append(data)

    if host['ILOFirmware'] < 1.55 and '(iLO 1)' in host['ILOType']:
        data = {'cve': "CVE-2004-0525",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c01039573"}
        vulns.append(data)

    if host['ILOFirmware'] < 1.81:
        data = {'cve': "CVE-2005-2552",
                'info': "https://marc.info/?l=bugtraq&m=112369495001738&w=2"}
        vulns.append(data)

    if ('(iLO 1)' in host['ILOType'] and
            host['ILOFirmware'] >= 1.70 and
            host['ILOFirmware'] <= 1.87) \
        or \
        ('(iLO 2)' in host['ILOType'] and
         host['ILOFirmware'] >= 1.00 and
         host['ILOFirmware'] <= 1.11):
        data = {'cve': "CVE-2006-6608",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c00800677"}
        vulns.append(data)

    # very, very weak check
    #if '(iLO 2)' in host['ILOType'] or \
    #   '(iLO 3)' in host['ILOType']:
    #    data = {'cve': "CVE-2011-4158",
    #            'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03082006"}
    #    vulns.append(data)

    if ('(iLO 3)' in host['ILOType'] and host['ILOFirmware'] <= 1.28) \
        or \
        ('(iLO 4)' in host['ILOType'] and
         host['ILOFirmware'] <= 1.11):
        data = {'cve': "CVE-2012-3271",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03515413"}
        vulns.append(data)

    # CVE-2013-4784: cipher 0 issue - http://fish2.com/ipmi/cipherzero.html

    # CVE-2013-4805
    if ('(iLO 3)' in host['ILOType'] and host['ILOFirmware'] < 1.61) \
        or \
        ('(iLO 4)' in host['ILOType'] and
         host['ILOFirmware'] < 1.30):
        data = {'cve': "CVE-2013-4805",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03844348"}
        vulns.append(data)

    if ('(iLO 3)' in host['ILOType'] and host['ILOFirmware'] < 1.65) \
        or \
        ('(iLO 4)' in host['ILOType'] and \
         host['ILOFirmware'] < 1.32):
        data = {'cve': "CVE-2013-4842",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03996804-1"}
        vulns.append(data)

    if ('(iLO 3)' in host['ILOType'] and host['ILOFirmware'] < 1.65) \
        or \
        ('(iLO 4)' in host['ILOType'] and \
         host['ILOFirmware'] < 1.32):
        data = {'cve': "CVE-2013-4843",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c03996804-1"}
        vulns.append(data)

    if ('(iLO 2)' in host['ILOType'] and host['ILOFirmware'] <= 2.23):
        data = {'cve': "CVE-2014-2601",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04244787"}
        vulns.append(data)

    if ('(iLO 2)' in host['ILOType'] and host['ILOFirmware'] < 2.27) \
        or \
        ('(iLO 4)' in host['ILOType'] and \
         host['ILOFirmware'] < 2.03):
        data = {'cve': "CVE-2014-7876",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04486432"}
        vulns.append(data)

    if ('(iLO 2)' in host['ILOType'] and host['ILOFirmware'] < 2.27) \
        or \
        ('(iLO 3)' in host['ILOType'] and \
         host['ILOFirmware'] < 1.82) \
        or \
        ('(iLO 4)' in host['ILOType'] and \
         host['ILOFirmware'] < 2.10):
        data = {'cve': "CVE-2015-2106",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04582368"}
        vulns.append(data)

    if ('(iLO 3)' in host['ILOType'] and host['ILOFirmware'] < 1.85) \
        or \
        ('(iLO 4)' in host['ILOType'] and \
         host['ILOFirmware'] < 2.22):
        data = {'cve': "CVE-2015-5435",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04785857"}
        vulns.append(data)

    if ('(iLO 3)' in host['ILOType'] and host['ILOFirmware'] < 1.88) \
        or \
        ('(iLO 4)' in host['ILOType'] and \
         host['ILOFirmware'] < 2.44):
        data = {'cve': "CVE-2016-4375",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c05236950"}
        vulns.append(data)

    if ('(iLO 4)' in host['ILOType'] and host['ILOFirmware'] < 2.53):
        data = {'cve': "CVE-2017-12542",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03769en_us"}
        vulns.append(data)

    if ('(iLO 2)' in host['ILOType'] and host['ILOFirmware'] == 2.29):
        data = {'cve': "CVE-2017-8979",
                'info': "https://support.hpe.com/hpsc/doc/public/display?docId=hpesbhf03797en_us"}
        vulns.append(data)
    return vulns

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract potential HPE iLO issues from nmap scan.')
    parser.add_argument('nmaplog', type=str, help='nmap XML log to parse')
    args = parser.parse_args()
    XML_ROOT = ET.parse('ilo04suche.xml').getroot()

    # find all host with iLO
    SEEN_HOSTS = set()
    RELEVANT_HOSTS = []
    for h in XML_ROOT.findall('host'):
        for info in extract_ilo_information(h):
            if info['host'] not in SEEN_HOSTS:
                RELEVANT_HOSTS.append(info)
                SEEN_HOSTS.add(info['host'])

    # print all potential issues
    print("### iLO issue scanner ###")
    for h in RELEVANT_HOSTS:
        VULNS = detect_cve(h)
        for v in VULNS:
            print("{0}: {1}".format(h['host'], v['cve']))

