#!/usr/bin/python

import os
import requests


# Getting the VirusToal API key. If it's not populated in the local variable, then it checks the system's environment variables.
def get_api_key():
    api_key = ''
    if api_key == '':
        try:
            api_key = os.environ['API_KEY']
        except KeyError:
            print "Can't locate VirusToal API Key. Please set the api_key variable or the API_KEY environment variable."
    return api_key


# Function to retrieve URL scan reports. This does not scan a URL. It simply just checks VT for already submitted URLs.
def url_scan_report(api_key, subject_url):
    api_endpoint = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': subject_url}
    response = requests.get(api_endpoint, params=params)
    if reach_api_limit(response) is True:  # reach_api_limit is a global lambda function defined below main().
        print '[ERROR:]: ' + response.headers['X-Api-Message']
    try:
        response_dict = response.json()
        for key in response_dict.keys():
            total_num_from_report = response_dict['total']
            total_positives_from_report = response_dict['positives']
            return {'total_num_of_scanners': total_num_from_report,
                    'positives': total_positives_from_report}
    except ValueError:
        print "[ERROR:]: Functon urlReport() didn't return anythng."


# Function to scan a URL. This function does submit a URL to be scanned (not just get a report of a previous scan)
def scan_url(api_key, url_to_scan):
    api_endpoint = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url': url_to_scan}
    response = requests.post(api_endpoint, data=params)
    if reach_api_limit(response) is True:  # reach_api_limit is a global lambda function defined below main().
        print '[ERROR:]: ' + response.headers['X-Api-Message']
    response_dict = response.json()
    permalink = response_dict['permalink']
    print permalink


def main():
    api_key = get_api_key()
    url_scan_report_resutls = url_scan_report(api_key, '[WEBSITE_NAME]')
    scan_url_results = scan_url(api_key, '[WEBSITE_NAME]')


# Global lambda function to see if the VirusToal API limit has been reached.
reach_api_limit = lambda x: (True if x.status_code == 204 else False)


if __name__ == '__main__':
    main()