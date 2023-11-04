#! /usr/bin/python3

import requests
import re
from bs4 import BeautifulSoup
from tabulate import tabulate

#extract IoC patterns
def extract_patterns(text, pattern):
    matches = re.findall(pattern, text, re.IGNORECASE)
    return list(set(matches))


#Scrape and extract data from website.
def scrape_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        page_text = response.text

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(page_text, 'html.parser')

        # Extract all the visible text within the HTML document
        webpage_text = soup.get_text()

        # Define regex patterns for IP addresses, domains, MD5, SHA-1, and SHA-256.
        ip_regex = r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b'
        domain_regex = r'\b(((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,63})\b|(?!pdf|docx?|xlsx?|txt|jpg|jpeg|png|exe|dll|js|vbs|bat|ps1|zip|rar|7z|tar|gz|bin|dat|csv|json|html|css|xml|php|asp|py|rb|java|cpp|h|c|swift|go|lua|js|ts|jsx|tsx|sql|db|ini|cfg|conf|yaml|yml|sh|log|csv|tsv|sql|db|bak|backup)[a-z0-9]+\b'
        md5_regex = r'\b[a-f0-9]{32}\b'
        sha1_regex = r'\b[a-f0-9]{40}\b'
        sha256_regex = r'\b[a-f0-9]{64}\b'

        #Extract data using the defined patterns
        ip_addresses = extract_patterns(webpage_text, ip_regex)
        domains = extract_patterns(webpage_text, domain_regex)
        md5_hashes = extract_patterns(webpage_text, md5_regex)
        sha1_hashes = extract_patterns(webpage_text, sha1_regex)
        sha256_hashes = extract_patterns(webpage_text, sha256_regex)
        
        #Remove empty values and unwanted characters
        ip_addresses = [ip.rstrip("',[]()")  for ip in ip_addresses if ip]  # Remove empty strings
        domains = [domain[0].rstrip("',[]()") for domain in domains if domain and domain[0] and not all(char in "()'" for char in domain)]  # Remove empty and undesired values
        md5_hashes = [md5.rstrip("',[]()")  for md5 in md5_hashes if md5]
        sha1_hashes = [sha1.rstrip("',[]()")  for sha1 in sha1_hashes if sha1]
        sha256_hashes = [sha256.rstrip("',[]()")  for sha256 in sha256_hashes if sha256]


        print('\n Website: ' + url)
        #Create key value pairs for table
        table = {'IP Addresses': ip_addresses, 'Domains': domains, 'MD5': md5_hashes, 'SHA1': sha1_hashes, 'SHA256': sha256_hashes}
        # Print the table
        print(tabulate(table, headers='keys',tablefmt='fancy_grid'))
        print("\n")


    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching {url}: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# List of URLs to scrape
urls = input("Please enter a URL or list of URLs separated by spaces: \n").split()

def main():
    for url in urls:
        scrape_website(url)

if __name__ == "__main__":
    main()
