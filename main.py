import requests
import sys
from pprint import pprint

def main(argv):
    length = len(argv)
    if(length >= 2):
        if(argv[1] == "-h"):
            try:
                main.hash = argv[3]
            except:
                print("Please enter a hash")
                quit()
            CheckUsingHash(argv)
        elif(argv[1] == "-f"):
            try:
                main.path = argv[3]
            except:
                print("Please enter the file path")
                quit()
            CheckUsingFile(argv)
    elif(length > 2):
        print("Please input only one file path")
    else:
        print("Please input the file path")

def CheckUsingHash(argv):
    url = "https://www.virustotal.com/api/v3/files/" + str(main.hash)
    header = {"x-apikey": "-----APIKEY-----"}
    response = requests.get(url, headers=header)
    data = response.json()
    VirusTotalResult = data["data"]["attributes"]
    if(argv[2] == "-r"):
        pprint(VirusTotalResult["last_analysis_stats"])
    elif(argv[2] == "-rv"):
        pprint(data["data"]["attributes"]["last_analysis_results"])

def CheckUsingFile(argv):
    url = "https://www.virustotal.com/api/v3/files"
    header = {"x-apikey": "-----APIKEY-----"}
    file = {"file": open(main.path, "rb")}
    response = requests.post(url, headers=header, files=file)
    data = response.json()
    VirusTotalID = data["data"]["id"]
    url = "https://www.virustotal.com/api/v3/analyses/" + VirusTotalID
    response = requests.get(url, headers=header)
    data = response.json()
    if (argv[2] == "-r"):
        pprint(data["data"]["attributes"]["stats"])
    elif (argv[2] == "-rv"):
        main.hash = data["meta"]["file_info"]["sha256"]
        print(main.hash)
        CheckUsingHash(argv)

main(sys.argv)
