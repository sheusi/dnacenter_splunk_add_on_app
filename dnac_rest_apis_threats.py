# -*- coding: utf-8 -*-
"""
Cisco DNA Center Command Runner
Copyright (c) 2019 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Stefan Heusi, Cisco,"
__email__ = "sheusi@cisco.com"
__version__ = "0.0.1"
__copyright__ = "Copyright (c) 2020 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import os
import sys
import time
import datetime
import requests
import urllib3
import json

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth
urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


# Cisco DNA Center info
username = 'sheusi'
password = 'Stefan123'
DNAC_URL = 'https://10.62.107.4'
DNAC_AUTH = HTTPBasicAuth(username, password)

def get_dnac_jwt_token(dnac_auth):
    """
    Create the authorization token required to access DNA C
    Call to Cisco DNA Center - /api/system/v1/auth/login
    :param dnac_auth - Cisco DNA Center Basic Auth string
    :return: Cisco DNA Center JWT token
    """
    url = DNAC_URL + '/dna/system/api/v1/auth/token'
    header = {'content-type': 'application/json'}
    response = requests.post(url, auth=dnac_auth, headers=header, verify=False)
    dnac_jwt_token = response.json()['Token']
    return dnac_jwt_token


def pprint(json_data):
    """
    Pretty print JSON formatted data
    :param json_data: data to pretty print
    :return None
    """
    print(json.dumps(json_data, indent=4, separators=(' , ', ' : ')))

def get_epoch_current_time():
    """
    This function will return the epoch time for the {timestamp}
    :return: epoch time including msec
    """
    epoch = time.time() * 1000
    return int(epoch)

### adding in variables to time
from datetime import timedelta

def get_timedelta_60s():
    """
    This function gives us timedelta to be able to add in seconds.
    :return: epoch time minus X seconds
    """
    delta1 = get_epoch_current_time() - timedelta(seconds=60)
    return int(delta1)


def get_timedelta_10m():
    """
    Function will return stated value minus stated time
    :return:
    """
    delta2 = get_epoch_current_time() - timedelta(minutes=10)
    return int(delta2)


def get_timedelta_1week():
    """
    This function gives us timedelta minus stated time
    :return: epoch time minus X
    """
    delta3 = get_epoch_current_time() - timedelta(days=7)
    return int(delta3)


def get_threat_summary(start_time, end_time, dnac_jwt_token ):
    """
     Post Request optional Paramter structure
     {
        "startTime": "integer",
        "endTime": "integer",
        "siteId": [
            "string"
        ],
        "threatLevel": [
            "string"
        ],
        "threatType": [
            "string"
        ]
     }

    # Samples to filter resonse based on above input structure
    # param = { 'threatLevel': ['Informational'] }
    # param = { 'threatLevel': ['High'] }
    # param = { }
    """

    param = { }
    url = DNAC_URL + '/dna/intent/api/v1/security/threats/summary'
    header = {'accept': 'application/json', 'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    network_threat_response = requests.post(url, data=json.dumps(param), headers=header, verify=False)
    network_threat_json = network_threat_response.json()
    network_threat = network_threat_json
    return network_threat


def get_threat_detail_count(start_time, end_time, dnac_jwt_token ):
    """
     Post Request optional Paramter structure

    {
        "offset": "integer",
        "limit": "integer",
        "startTime": "integer",
        "endTime": "integer",
        "siteId": [
            "string"
        ],
        "threatLevel": [
            "string"
        ],
        "threatType": [
            "string"
        ],
        "isNewThreat": "boolean"
    }

    # Samples to filter resonse based on above input structure
    # param = { 'threatLevel': ['Informational'] }
    # param = { 'threatLevel': ['High'] }
    # param = { }
    """

    param = { }
    url = DNAC_URL + '/dna/intent/api/v1/security/threats/details/count'
    header = {'accept': 'application/json', 'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    network_threat_detail_count_response = requests.post(url, data=json.dumps(param), headers=header, verify=False)
    network_threat_detail_count_json = network_threat_detail_count_response .json()
    network_threat_detail_count = network_threat_detail_count_json
    return network_threat_detail_count


def get_threat_details(start_time, end_time, dnac_jwt_token ):
    """
     Post Request optional Paramter structure
     {
        "offset": "integer",
        "limit": "integer",
        "startTime": "integer",
        "endTime": "integer",
        "siteId": [
            "string"
        ],
        "threatLevel": [
            "string"
        ],
        "threatType": [
            "string"
        ],
        "isNewThreat": "boolean"
    }

    # Samples to filter resonse based on above input structure
    # param = { 'threatLevel': ['Informational'] }
    # param = { 'threatLevel': ['High'] }
    # param = { 'isNewThreat': True }
    # param = { }
    """

    param = { }
    url = DNAC_URL + '/dna/intent/api/v1/security/threats/details'
    header = {'accept': 'application/json', 'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    network_threat_details_response = requests.post(url, data=json.dumps(param), headers=header, verify=False)
    network_threat_details_json = network_threat_details_response.json()
    network_threat_details = network_threat_details_json
    return network_threat_details




def main():

    start_time = get_epoch_current_time()
    end_time = get_epoch_current_time()
    # get the Cisco DNA Center Auth
    dnac_auth = get_dnac_jwt_token(DNAC_AUTH)


    # API1 -- Threat Summary

    # get threat summary and write to splunk
    # get_threat_summary(start_time, end_time, dnac_auth)

    # remove comment from below line when writing to splunk, and mark the printing to console as comment with indent=2)
    #print(json.dumps([{'threat_summary':get_threat_summary(start_time, end_time, dnac_auth)}]))

    # for printing nicely to a console, when developing on IDE
    print(json.dumps([{'threat_summary':get_threat_summary(start_time, end_time, dnac_auth)}],indent=2))

    # API 2 -- Threat deail Counts

    # get threat detail counts and write to splunk
    # get_threat_detail_count(start_time, end_time, dnac_auth)

    # print(json.dumps([{'threat_detail_count':get_threat_detail_count(start_time, end_time, dnac_auth)}]))

    # for printing nicely to a console, when developing on IDE
    print(json.dumps([{'threat_datail_count':get_threat_detail_count(start_time, end_time, dnac_auth)}],indent=2))

    # API 3 -- Threat Details

    # get threat details and write to splunk
    # get_threat_details(start_time, end_time, dnac_auth)
    # print(json.dumps([{'threat_details':get_threat_details(start_time, end_time, dnac_auth)}]))
    # for printing nicely to a console, when developing on IDE
    print(json.dumps([{'threat_datails':get_threat_details(start_time, end_time, dnac_auth)}],indent=2))


if __name__ == '__main__':
    main()
