# Local Falcon Sensor Modifications
Name of folder subject to change.

Directory is focused on scripts that modify the Falcon sensor settings locally. For now that means the Sensor Grouping Tag on Windows.

## Editing Windows Sensor Grouping Tags
The edit_windows_sensor_tags.ps1 script provides a way one might use for ease of modifications to sensor grouping tags through RTR scripts.

This can save time for customers and Falcon Admins. One example case involves server owners requesting maintenance tokens to update tags they missed at initial install. Whether they intend to use CsSensorSettings.exe or fully reinstall on Windows. A Falcon Admin or team member with RTR-Active Responder/RTR-Admin role could handle the sensor grouping tag update without handing over the sensitive maintenance token.

If bulk RTR scripting were developed to call on a prepared version of this script, one could mass update targeted Windows hosts. Due care is always advised of course.