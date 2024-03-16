from main import api_endpoint
import requests

def make_api_call(url, github_pat):
    headers = {
        "Authorization": "token {}".format(github_pat),
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(response.status_code, response.text)
    response_json = response.json()
    while "next" in response.links.keys():
        response = requests.get(response.links["next"]["url"], headers=headers)
        response_json.extend(response.json())
    return response_json

# Add a new function to get the custom properties of a repo
def get_repo_properties(repo_name, github_pat):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_pat}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"{api_endpoint}/repos/{repo_name}/properties/values"
    response = requests.get(url, headers=headers)
    if not response.ok:
        raise Exception(response.status_code, response.text)
    response_json = response.json()
    # Parse the response and return a dictionary of property names and values
    properties = {}
    for prop in response_json:
        properties[prop["property_name"]] = prop["value"]
    return properties