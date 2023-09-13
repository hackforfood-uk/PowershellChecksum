# PowershellChecksum
This script was created for monitoring a directory (typically a web directory or other (cannarytoken)) for modification. This is designed to run as a scheduled task to regularly monitor this directory - should the hash change the script will output the expected hash and the new has to a log file as well as the ability to be able to syslog this to a SIEM solution or other.

**How to set the operates**

There isn't any specalist setup really needed as the script is self sufficient - e.g. it will create the necessary registry key and log file which are all set as variables in the script below is a quick over view.


If the sript has not run before it will create a control checksum and create a registry string called 'ControlChecksum' in HKLM\Software\CyberSecurityMonitoring it will then compute a combined hash of 
