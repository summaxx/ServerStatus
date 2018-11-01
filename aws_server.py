#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import boto3
import urllib,urllib2
import random
import string
import threading

ACCESS_KEY_ID = 'AKIAJSNPBEMBIQW4CZ4A'
ACCESS_SECRET_KEY = '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'
#IPURL = 'http://s3.haoss.top/mod_mu/func/changip?key=gFL87HM6NhzE7VB5'
IPURL = 'http://s3.freefly.top/mod_mu/func/changip?key=UQCpT79RXuXzmoRi'
regions = {'1': 'ap-northeast-1', '2': 'ap-southeast-1', '3': 'us-west-2'}

def aws_changip(oip, reg):
    client = boto3.client('lightsail', aws_access_key_id=ACCESS_KEY_ID, aws_secret_access_key=ACCESS_SECRET_KEY, region_name=regions[reg])
    res = client.get_instances()
    #print res
    for v in res['instances']:
        print v['name'] + v['publicIpAddress']
        if v['publicIpAddress'] == oip:
            res = client.get_static_ips()
            print "find ip"
            for ip in res['staticIps']:
                if ip['ipAddress'] == oip:
                    ipname = ''.join(random.sample(string.ascii_letters + string.digits, 8))
                    client.allocate_static_ip(staticIpName=ipname)
                    r = client.get_static_ip(staticIpName=ipname)
                    #print('allocate new ip %s' % r['staticIp']['ipAddress'])
                    try:
                        ret = httpchangip(1, oip, r['staticIp']['ipAddress'])
                    except Exception, e:
                        ret = 0
                        print "url open error " + e.message
                    if ret > 0:
                        client.detach_static_ip(staticIpName=ip['name'])
                        client.release_static_ip(staticIpName=ip['name'])
                        client.attach_static_ip(staticIpName=ipname,instanceName=v['name'])
                    else:
                        client.release_static_ip(staticIpName=ipname)
                    return ret
            break
    return 0

def httpchangip(s, ip, nip):
   url = '%s&s=%s&ip=%s&nip=%s' % (IPURL, s, ip, nip)
   print(url)
   try:
       req = urllib2.Request(url)
       res = urllib2.urlopen(req, timeout=10)
       res = res.read()
       print res
       if res.find('1') > 0:
         return 1
   except:
      return 0
   return 0


def awsServer(client, addr):
    data = client.recv(512).strip()
    #print(addr[0] + ': ' + data)
    if len(data) > 0:
        if (data[0] <= '3') and (data[0] > '0'):
            ret = aws_changip(addr[0], data[0])
            if ret == 0:
                print "change fail"
    client.close()

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 1024))
    server.listen(5)
    print "server start!"
    try:
        while True:
            c, addr = server.accept()
            t = threading.Thread(target=awsServer, args=(c, addr))
            t.start()
    except KeyboardInterrupt, e:
        pass
    server.close()
    print "server stop"
