#!/usr/bin/env python
import requests
import bs4

#scrape cwe for cwe name and description

response = requests.get('https://cwe.mitre.org/data/definitions/200.html')
soup = bs4.BeautifulSoup(response.text, "lxml")
# Pull 'CWE-##: Name' from the webpage
headerII = soup.select('h2')
for header in headerII:
    print header.string
    # pull the cwe number so we can get the div with the text
    cwe_num = header.string.rsplit(':', 1)[0].rsplit('-', 1)[1]

# The div with the cwe description is wrapped in a div with the class 
# "div.oc_200_Description", if the cwe id was 200. We need to pull this div
# so we can more easily parse for the simple description within the div
desc_div = soup.find("div", id= "oc_"+cwe_num+"_Description")

# now we have to iterate for the div that holds the description we want. Due
# to the layout of the page we know it's the first description (they didn't use
# a useful tag
for tag in desc_div:
    p = soup.find_all("div", {"class":"indent"})
    print p[0].text
