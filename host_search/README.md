# Host Search

The falcon_host_search_site.py script offers a way one could publish an internal web page for end users to search and confirm their workload is secured by a Falcon sensor. Please be sure to download both the Python script and the accompanying templates folder.

## Caution!
This solution is a potential method of discovery of your managed Falcon environment. It is highly recommended that this solution be secured within your organization's network or at the very least restricted from the public internet. One might use internal network rules, custom authentication restricted to your staff, or other methods as suitable to your environment.

## Benefits
Primary benefits include time saved for internal customers submitting tickets/requests for validation, as well as the time needed for Falcon support staff to search, capture evidence, and respond to customers.

A secondary benefit is it can negate the desire of some internal customers to request read-only access in the Falcon console simply to self-audit their coverage. Along with the overhead that can result from such arrangements.

## Requirements
- Falcon API client ID and its secret. The API client must include scope of 'Hosts: Read'
- FalconPy SDK
- Python 3.7 or later is required for the FalconPy SDK. The script was initially written and tested with Python 3.10. Please keep this in mind for compatibility of changes in the future.
- Flask is required for this iteration which operates through a web page.
- The 'templates' folder must be in the same directory where you store the Python script. This allows Flask to locate the HTML files within.

## Work in progress note
The details.html file is not in a production-ready state. That file still needs to be recreated from a past implementation.

## More documentation to come
