Clamnix is a Splunk app that distributes a stripped-down clam database that only contains "Unix" signatures.

Install this by putting clamnix in the $SPLUNK_HOME/etc/apps and $SPLUNK_HOME/etc/deployment-apps on your Splunk Deployment Server.
You will need to assign the Clamnix app to the serverclasses in Forwarder Management.


Stats on my home lab:
Reduced size of database from 240MB to 4MB
Reduced resident memory of scan from over 500MB to around 45MB

