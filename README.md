# PowershellChecksum
This script was created for monitoring a directory (typically a web directory or other (cannarytoken)) for modification. This is designed to run as a scheduled task to regularly monitor this directory - should the hash change the script will output the expected hash and the new hash to a log file as well as the ability to be able to syslog this to a SIEM solution or other.

**How to setup the script**

There isn't any specalist setup really needed as the script is self sufficient - e.g. it will create the necessary registry key and log file which are all set as variables in the script below is a quick over view. The only setup requried by a consumer is to configure the scheduled task to run the powershell script (there is an example XML in the respository) and then configure the necessary variables such as SIEM output and directory to monitor.

**How it works in short**

If the sript has not run before it will create a control checksum and create a registry string called 'ControlChecksum' in HKLM\Software\CyberSecurityMonitoring, following this it will then compute a combined hash of all of the files in the monitoring directory and write value to the previously created registry key.

On next run if the hash is the same the script will quit, however if it changes it will log the changes to the log directory and if SIEM intergration is configured it will log this out.

All script actions are logged in the log directory - again this is customiseable.

**Disclaimer**

You use this script at your own risk.

**Support / Contact**

Please feel free to create an issue or message me - I cannot garauntee I will always been able to reply but any suggestions changes please let me know.
