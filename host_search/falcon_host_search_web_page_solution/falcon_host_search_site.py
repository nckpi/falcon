"""
This sript takes a list of hostnames and/or cloud instance IDs, queries the
CrowdStrike APIs for them, and returns the following:

Hostname - The hostname or instance ID of the system as reported to Falcon
Found - True/False if the hostname/ID was found with a Falcon sensor installed and communicating
Agent Version - The version of the Falcon sensor currently running on the system
Last Check-in Time - The last time the sensor was seenby the CrowdStrike Falcon console
First Check-in Time - The first time the sensor was seen by the CrowdStrike Falcon console
Tags - Any Grouping Tags applied to the system, whether FalconGroupingTag or SensorGroupingTag
Customer ID - The CID, or CrowdStrike tenant, that the sensor is reporting to
Cloud Instance ID - If applicable. e.g., An AWS instance ID looks like "i-0d87dDf87D..."
Unique Agent ID - Also referred to as the Agent ID (AID), the unique ID of a sensor. Helps with duplicate hostnames

Requirements:
- Falcon API client ID and its secret. The API client must include scope of 'Hosts: Read'
- FalconPy SDK
- Python 3.7 or later is required for the FalconPy SDK. The script was initially written and tested
  with Python 3.10. Please keep this in mind for compatibility of changes in the future.
- Flask is required for this iteration which operates through a web page.
"""
# -*- coding: utf-8 -*-
import concurrent.futures
import re

from flask import Flask, render_template, request

from falconpy import Hosts

app = Flask(__name__)


@app.route("/")
def upload_form():
    """Loading home page. This will contain a textarea to submit a list of hosts"""
    return render_template("home.html")

# Customer ID Dictionary. Update if CIDs are added or subtracted in the future.
cid_dict = {
    "1234567890qwertyuiopasdfghjkl": "Company Name",
    "0987654321poiuytrewqlkjhgfdsa": "Business Segment",
    "67890-54321trewyuiopgfdshjkla": "Sister Company",
    "09876123456mnbvzxcvbasdftygwk": "Acronyms R Us",
}


def file_parse(submitted_list):
    """Takes text list of names provided, removes trailing whitespace,
    and uses RegEx to split instance IDs from hostnames for return"""

    # Clean list
    host_items_split = [host for host in submitted_list.split("\n")]
    host_list = [i.strip() for i in host_items_split]
    while "" in host_list:
        host_list.remove("")
    
    # Check if too many names were entered. If so, return false values to main()
    host_list_len = len(host_list)
    print("Number of hosts entered: ", str(host_list_len))
    if len(host_list) > 5000:
        print(
            "More than 5,000 names entered. Script will inform user it will not proceed"
        )
        return (False, False)
    
    # Create two lists, separate instance IDs from hostnames
    iname_list, hname_list = [], []
    for host_or_id in host_list:
        # Remove domains and leave base hostname
        host_or_id = re.sub(r"\..*", "", host_or_id)
        if re.match(r"^i-\b.*$", host_or_id):
            iname_list.append(host_or_id)
        else:
            hname_list.append(host_or_id)
    
    return (iname_list, hname_list)

def cs_query_devices(falcon, iname_list, hname_list):
    """Gets Host IDs/AIDs from hostnames or instance IDs,
    which are later used to return desired host details"""

    is_found = False
    aid_list = []
    host_info_list = []

    def search_inames(iname):
        """Search by instance ID"""
        aid = None
        iname_search = falcon.query_devices_by_filter_scroll(
            # Search limited to 50 matches. Default limit is 100. Set to balance finding partial
            # matches/duplicates while limiting misuse for environment discovery with partial names
            limit = 50,
            # Sorts most recently seen matches to the top
            sort="last_seen.desc",
            filter=f"instance_id:*'*{iname}*'",
        )

        if iname_search["status_code"] == 200:
            aid = iname_search["body"]["resources"]
            if aid:
                aid_list.append(aid)
            else:
                device_details = f"{iname},{is_found}"
                host_info_list.append(device_details)
        # If status_code on API call is not 200 then there was an error. Note and skip.
        else:
            host_info_list.append(
                f"{iname}, Search experienced an error. "
                "Please try this name again in a smaller search list."
            )
    
    def search_hnames(hname):
        """Search by system hostname"""
        aid = None
        hname_search = falcon.query_devices_by_filter_scroll(
            # Search limited to 50 matches. Default limit is 100. Relevant to duplicate names.
            limit = 50,
            # Sorts most recently seen matches to the top
            sort = "last_seen.desc",
            filter = f"hostname:*'{hname}*'",
        )

        if hname_search["status_code"] == 200:
            aid = hname_search["body"]["resources"]
            if aid:
                aid_list.append(aid)
            else:
                device_details = f"{hname},{is_found}"
                host_info_list.append(device_details)
        # If status_code on API call is not 200 then there was an error. Note and skip.
        else:
            host_info_list.append(
                f"{hname}, Search experienced a transient error. "
                "Please try this name again in a smaller search list."
            )
    """Execute iname and hname searches with multithreading. Test response times if committing
    changes to max_workers. 200 or 300 may actually take longer than 100 depending on search size."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(search_inames, iname_list)
        executor.map(search_hnames, hname_list)

    # Flatten aid_list to prevent incomplete data output caused by sub-lists
        aid_list = [i for sub_list in aid_list for i in sub_list]
        print("Number of Falcon Sensors Found:", len(aid_list))
        print("Names not found:", len(host_info_list))

        return (aid_list, host_info_list)
    
def cs_detail_search(falcon, aid_list, host_info_list):
    """Retrieve host details using the collected AIDs, if 5000 or fewer. While
    we could break up large numbers of results into multiple lists and query them
    in batches of 5000 we want to dissuade users from reckless and costly partial searches"""

    if len(aid_list) == 0:
        host_info_list.apppend(
            "Names provided were not found managed in CrowdStrike Falcon. "
            "If some names reported a transient API error then please try them in a new search."
        )
    
    elif 0 < len(aid_list) <= 5000:
        details_response = falcon.get_device_details(ids=aid_list)["body"]["resources"]
        for detail in details_response:
            # Get basic variables
            is_found = True
            hostname = detail["hostname"]
            host_id = detail["device_id"]
            agent_version = detail["agent_version"]
            last_seen = detail["last_seen"]
            first_seen = detail["first_seen"]

            # Instance ID
            try:
                instance_id = detail["instance_id"]
            except KeyError:
                instance_id = "N/A"
            
            # Convert tags from list to string, delimit with ; to
            # avoid issue with CVS output of multiple tags
            try:
                tags = detail["tags"]
                tags = ";".join(tags)
            except KeyError:
                tags = "N/A"
            
            # Attempt to provide friendly CID name via CID dictionary
            cid = detail["cid"]
            cid_name = cid_dict.get(cid, "Name not found")
            cid = f"{cid_name} : {cid}"

            # Finally, format device details in correct order and append to list
            device_details = f"{hostname},{is_found},{agent_version},{last_seen}\
                ,{first_seen},{tags},{cid},{instance_id},{host_id}"
            host_info_list.append(device_details)

    else:
        host_info_list.append(
            f"{len(aid_list)} hosts found. Please reduce the number of partial "
            "names to stay under 5000 results. Any names above that reported "
            "IsFound as False were confirmed not to be found."
        )
    
    return host_info_list


@app.route("/submit", methods=["GET", "POST"])
def upload_file():
    """Triggers when the Submit button is clicked on home.html page. Runs API search."""
    client_id = "REDACTED"
    client_secret = "REDACTED"
    submitted_list = request.form["textarea"]
    iname_list, hname_list = file_parse(submitted_list)

    if iname_list and hname_list == False:
        host_info_list = [
            "Too many names to search. Please try again with fewer than 5000 names."
        ]
    
    else:
        falcon = Hosts(client_id=client_id, client_secret=client_secret)
        aid_list, host_info_list = cs_query_devices(falcon, iname_list, hname_list)
        host_info_list = cs_detail_search(falcon, aid_list, host_info_list)


if __name__ == "__main__":
    app.run(port=8000, debug=True, host="0.0.0.0")
