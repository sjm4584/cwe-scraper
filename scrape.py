#!/usr/bin/env python
import requests
import bs4
import csv

#scrape cwe for cwe name and description

def make_request(url):
    return requests.get(url)

'''
Name:       create_soup()
Purpose:    Create our soup object so we can parse things in formulas
Parameters: <response> which is the web request response we want to parse
Return:     <soup> our soup object
'''
def create_soup(response):
    soup = bs4.BeautifulSoup(response.text, "lxml")
    return soup


'''
Name:       cwe_num_parser()
Purpose:    Parses for our cwe-number which is needed to parse the description
Parameters: <response>, the response to our request; <soup> our BeautifulSoup
            object we are using to parse
Return:     the cwe number
'''
def cwe_num_parser(response, soup):
    # Pull 'CWE-##: Name' from the webpage
    headerII = soup.select('h2')
    for header in headerII:
        print header.string
        # pull the cwe number so we can get the div with the text
        return  header.string.rsplit(':', 1)[0].rsplit('-', 1)[1]


'''
Name:       description_parser()
Purpose:    Parses the simple description for our cwe
Parameters: <response>, the response to our request; <cwe_num>, the cwe number
            which is needed to find the div to parse out; <soup> our
            BeautifulSoup object we're using to parse
'''
def description_parser(response, cwe_num, soup):
    # The div with the cwe description is wrapped in a div with the class 
    # "div.oc_200_Description", if the cwe id was 200. We need to pull this div
    # so we can more easily parse for the simple description within the div
    desc_div = soup.find("div", id= "oc_"+cwe_num+"_Description")

    # now we have to iterate for the div that holds the description we want. Due
    # to the layout of the page we know it's the first description (they didn't use
    # a useful tag
    for tag in desc_div:
        p = soup.find_all("div", {"class":"indent"})
        return p[0].text


def main():
    url = 'https://cwe.mitre.org/data/definitions/1.html'
    lower_limit = input("[+] Starting record? ")
    upper_limit = input("[+] Ending record? ")
    success = []
    data = []
    f = open('cwes.csv', 'wt')
    writer = csv.writer(f)

    for i in range(lower_limit, upper_limit):
        url = 'https://cwe.mitre.org/data/definitions/'+str(i)+'.html'
        try:
            response = make_request(url)
            soup = create_soup(response)
            cwe_num = cwe_num_parser(response, soup)
            description = description_parser(response, cwe_num, soup)
            writer.writerow((cwe_num, description))
            print '[+] ', cwe_num, ':', description
            success.append(cwe_num)
        except:
            print "[!] Something bad happened"
        print '-'*25
    f.close()

    perc = float(len(success))/float(upper_limit)
    print float(perc)*100

if __name__ == '__main__':
    main()
