# Sensor Downloads

The sensor_download.py script exists to aid admins who need or want to downnload sensors for use with internal repositories.

Perhaps you need to provide all N-1 or N-2 sensors in a file share or SharePoint directory for as-needed use by system administrators.

sensor_download.py automates creation of directories with names matching the OS + OS Ver values to help organize the 20+ Linux sensors when downloading all at once.

- Fixed: When CrowdStrike created or stopped using a new OS grouping label (e.g., when they 
changed "RHEL 9" to "RHEL/Oracle 9"), and the script tried to download all N-1 or N-2 sensors with the -a option,
the script could run into a KeyError on the NMVER variable (current/previous/oldest) which was not handled and 
stopped download of all remaining sensors. Now a message will produce a note and the loop will finish the task.

Example message when 'Ubuntu 16/18/20 turned into 'Ubuntu 16/18/20/22' and there technically was no N-2 version available for that identifer:
"oldest version not available for Ubuntu 16/18/20/22. The OS grouping label likely was recently changed."