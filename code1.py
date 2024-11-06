import requests
import time
import os

# List of IP addresses to check
IPs = [
 
'51.195.88.32',   #example           
'192.168.15.1',   #example

]

# My VirusTotal API key

API_key = ''  # Replace with your actual API key
url = 'https://www.virustotal.com/api/v3/ip_addresses/'

# Output file paths
malicious_ip_file_path = os.path.join(os.path.expanduser("~"), "Desktop", "malicious_ip.txt")
whitelisted_ip_file_path = os.path.join(os.path.expanduser("~"), "Desktop", "whitelisted_ips.txt")

# Open the output files
with open(malicious_ip_file_path, 'w') as malicious_file, open(whitelisted_ip_file_path, 'w') as whitelisted_file:
    # Iterate through the list of IP addresses
    for ip in IPs:
        headers = {'x-apikey': API_key}  # Set the API key in headers

        # Make the API request
        response = requests.get(url + ip, headers=headers)

        # Debugging output
        print(f"Response for {ip}: {response.status_code} - {response.text}")

        # Check if the response was successful
        if response.status_code == 200:
            json_response = response.json()
            if 'data' in json_response:
                malicious_count = json_response['data']['attributes']['last_analysis_stats']['malicious']
                country = json_response['data']['attributes'].get('country', 'Unknown')  # Get the country

                if malicious_count <= 0:
                    whitelisted_file.write(f"{ip} is clean\n")
                else:
                    malicious_file.write(f"{ip} is Malicious, Detected by {malicious_count} solutions, Country: {country}\n")
            else:
                print(f"No data found for {ip}.")
        elif response.status_code == 404:
            print(f"{ip} not found in VirusTotal.")
        elif response.status_code == 403:
            print(f"Access denied for {ip}. Check your API key and limits.")
        else:
            print(f"Error fetching data for {ip}: {response.status_code} - {response.text}")

        # Pause to avoid hitting the API rate limit
        time.sleep(15)

print(f"Malicious IP results have been written to: {malicious_ip_file_path}")
print(f"Whitelisted IP results have been written to: {whitelisted_ip_file_path}")
