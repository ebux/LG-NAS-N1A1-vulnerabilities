# LG NAS N1A1 multiple vulnerabilities in Familycast #

## Discovered by: ##
Gergely Eberhardt (@ebux25) <gergely.eberhardt@search-lab.hu>

## Access: ##
Remote; unauthenticated access

## Tracking and identifiers: ##
CVE - None allocated.

## Platforms / Firmware confirmed affected: ##
- LG NAS N1A1 Version 10119, 10/04/2012
- [Product page](http://www.lg.com/us/support-product/lg-N1A1DD1)
  
## What is Familycast? ##
Familycast is a service running on top of the NAS functionality. According to LG, Familycast is an: "LG SMART TV exclusive application which allows the user to easily access and share photos, music, videos and other data saved on the net hard with their family with the TV remote control from anywhere around the globe."

## Vulnerabilities ##

### Insufficient function level access control ###
Although Familycast functionality requires the user to log in, most of the PHP scripts in the Familycast service under the `/familycast/interface/php/` folder do not perform any session checking. Thus, every file shared via this service can be accessed remotely and other vulnerabilities can be exploited without authentication.

### SQL injection in profile request ###
User profiles – containing various IDs and relationship types – are requested by the Familycast manager after login. To obtain the profile data, the `proc_type` (`=family_get`) and `id` parameters should be sent in a `POST` request. 

![image](https://github.com/ebux/LG-NAS-N1A1-vulnerabilities/LG-NAS-N1A1-vulnerabilities/familycast_sqli.png)
 
From these parameters, the `id` parameter is used in an SQL statement without sanitization, thus SQL injection is possible. By exploiting this SQL injection, an attacker can obtain the user names and password hashes of the Familycast service.

We note that this SQL injection is only an easily-exploited example. Since the application does not perform any sanitization or verification steps before executing SQL statements in general, other SQL injections may also be possible.

### Arbitrary file up- and download with directory traversal ###
The Familycast service contained a hidden simple upload form, providing an easy way to upload or download any files to or from its folder.  

![image](https://github.com/ebux/LG-NAS-N1A1-vulnerabilities/LG-NAS-N1A1-vulnerabilities/familycast_upload.png)

The `upload.html` file uses the `file.php` script to perform file copy, download, upload, retrieve, modify, move and delete operations. These operations also support multiple files and directories and use the file_name `POST` parameter without any kind of input validation. 

![image](https://github.com/ebux/LG-NAS-N1A1-vulnerabilities/LG-NAS-N1A1-vulnerabilities/familycast_dir_traversal.png)

The missing parameter verification leads to directory traversal, ultimately allowing access to any system file via this service.

### Sensitive information in log files ###
The NAS logs every event into the `/var/tmp/ui_script.log` file along with the event parameters. The login events are also inserted into this file along with the actual password hash. Since the NAS login process (different from the Familycast login process) requires sending the password hash, the parameter from the log file can be used to login to the NAS without reversing the plain text password.

![image](https://github.com/ebux/LG-NAS-N1A1-vulnerabilities/LG-NAS-N1A1-vulnerabilities/familycast_log.png)
 
## POC ##
A POC script is available to demonstrate the following problems:
- Insufficient function-level access control
- Arbitrary file upload and download with directory traversal
- SQL Injection in Familycast
- Sensitive information in log files

A video demonstration presenting the above problems – and how they can be combined to obtain admin access to the NAS – is also available.

## Recommendations ##
Update the firmware to the latest version [`firmware-N1A1_10124rfke.zip`](http://www.lg.com/us/support-product/lg-N1A1DD1). We also highly recommend not exposing the web interface of LG N1A1 NAS devices to the internet.
Timeline
SEARCH-LAB Ltd. tried to responsibly report these vulnerabilities to LG, but we were not able to find the appropriate contact within the company.
- 2015-03-10: We asked a security contact for reporting NAS vulnerabilities from the security representative of LG Mobile (we were in connection with them regarding vulnerabilities we discovered in LG Mobile devices).
- 2015-03-11: LG Mobile recommended sending the report through the official LG support contact form.
- 2015-03-14: We sent the findings to official LG support.  We have not received any answer yet.
- 2015-04-02: Since we have not received any answer from LG support, we contacted our national CERT to help finding a contact.
- 2015-10-02: Finally we found the right contact and LG updated the firmware to version 10124

## Links ##
- [Search-lab advisory](http://www.search-lab.hu/about-us/news/LG-NAS)
- [POC video](http://youtube.com/valami)

