# Script name: virus-total-api.py
# Description: Python script to find IPs with bad reputation by querying the Virus total API
# Input:
  # 1. New Line delimited file with IP addresses and placed in the same directory as this script
  # 2. Virus total API key
# Output
  # List of IPs with bad reputation and the score of each IP

import requests
import json
import time

# ENTER FILE NAME WITH IPS AND THE API KEY BELOW
file = "badips.txt"
APIKey = ''

def queryIP(apikey, ip_quad, bad_ip_list):
  vt_api = apikey
  for ip in ip_quad:
    url = "https://www.virustotal.com/api/v3/ip_addresses/"+ip
    payload={}
    headers = {
      'x-apikey': vt_api
    }
    response = requests.request("GET", url, headers=headers, data=payload).text
    data = json.loads(response)
    stats = data['data']['attributes']['last_analysis_stats']
    print("Results of IP ==>",ip,":", stats)
    if stats['malicious'] > 0 or stats['suspicious'] > 0 :
      bad_ip_list.append(ip)
  return bad_ip_list

if __name__ == "__main__":
  ip_list = []
  bad_ip_list = []
  file = open(file)
  for ip in file:
    ip = ip.strip("\n")
    ip_list.append(ip)
  file.close()
  
  # Due to API license limitation, only 4 IPs can be queries in a minute
  while len(ip_list) > 0:
    # Get IP list in groups of 4 IPs at a time
    ip_quad = ip_list[:4]

    # Send the IP quad to be queried by the API 
    response = queryIP(APIKey, ip_quad, bad_ip_list)
    # Delete the processed IP quad
    del ip_list[:4]

    if len(ip_list) > 0:
      print("Sleeping 60 seconds due to API license limitation")
      time.sleep(60)

  print("\n\n=============VirusTotal IP Reputation Results=============") 
  for bad_ip in bad_ip_list:
    print(bad_ip)
  print("\n")