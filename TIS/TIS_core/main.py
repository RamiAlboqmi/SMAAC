import json
import shutil
import csv
import string
import uuid
from collections import Counter
from pathlib import Path
from tokenize import Double
import subprocess
from urllib.parse import urlparse
import asyncio
import re

from kubernetes import client, config
import ast
import json
import time

from flask import Flask, jsonify, request
from stix2 import Environment, MemoryStore, Bundle, Identity, Relationship, KillChainPhase, ObservedData, Sighting, \
    AttackPattern, Note, Vulnerability
from stix2 import CompositeDataSource, FileSystemSink, FileSystemSource, MemorySource
from stix2 import Indicator
from stix2 import TAXIICollectionSink, ThreatActor
from stix2 import FileSystemStore
from datetime import datetime
from dateutil.relativedelta import relativedelta
import os
from pandas import *
app = Flask(__name__)
microservices_names = []

flag = False
@app.route("/hello")
def hello():
    return "Hello, Welcome to GeeksForGeeks"

def write_trusted_microservices_names():
    data = ""
    if (flag):
        config.load_kube_config()
    else:
        config.load_incluster_config()

    v1 = client.CoreV1Api()
    print("Listing pods with their IPs:")
    apis_api = client.AppsV1Api()
    resp = apis_api.list_namespaced_deployment(namespace="default")
    for i in resp.items:
        microservices_names.append(i.metadata.name)
        #print(f"Deployment Name: {i.metadata.name}")
    print("microservices_names====",microservices_names)





    return  "Done"

@app.route("/getservicenames", methods=["GET"])
def get_services_names():
    data = ""
    if (flag):
        config.load_kube_config()
    else:
        config.load_incluster_config()
    v1 = client.CoreV1Api()
    print("Listing pods with their IPs:")
    ret = v1.list_pod_for_all_namespaces(watch=False)
    count=0
    for i in ret.items:
        # print(f"{i.status.pod_ip}\t{'default'}\t{i.metadata.name}")
        all_pods = str(
            v1.read_namespaced_pod_ephemeralcontainers(i.metadata.name, i.metadata.namespace).spec.containers[0])
        all_pods_dic = ast.literal_eval(all_pods)
        image_name = all_pods_dic.get('image', "Not found")
        print('image_name:',image_name)
        print('count:',count)

        #print('i:',i)
        #print('i.metadata.name:',i.metadata.name)


        if i.metadata.namespace == "default":
            data = data + "," +  all_pods_dic.get('name', "Not found") + "&" + image_name
            #data.append(all_pods_dic.get('name', "Not found"))

        count = count  + 1

    """
    Endpoint to return values of the sample dictionary.
    """
    return  data, 200


def list_and_sacn_all_images():
    file_path = Path("assessment.txt")

    if file_path.exists():
        print(f"The file '{file_path}' exists.")
        # return
        return file_path.exists()
    else:
        print("The file is not found >>> "
              "Listing pods with their IPs:")
        if (flag):
            config.load_kube_config()
        else:
            config.load_incluster_config()
        #config.load_incluster_config()


        v1 = client.CoreV1Api()
        print("Listing pods with their IPs:")
        ret = v1.list_pod_for_all_namespaces(watch=False)
        for i in ret.items:
            #print(f"{i.status.pod_ip}\t{'default'}\t{i.metadata.name}")
            all_pods = str(v1.read_namespaced_pod_ephemeralcontainers(i.metadata.name,i.metadata.namespace).spec.containers[0])
            all_pods_dic = ast.literal_eval(all_pods)
            image_name = all_pods_dic.get('image', "Not found")
            app_name = all_pods_dic.get('name', "Not found")
            #print('image_name:',image_name)
            if i.metadata.namespace == "default":
                print("Image::::::::", image_name)
                print("App name", )
                run_trivy(image_name , app_name)
        #print("---------------------------------------------------------------------------------------")

def run_trivy(image_name, app_name):



    #print("Now in run_trivy() to perform scanning")
    # process = subprocess.run(["trivy", "image", image_name], capture_output=True, text=True)



    #pwd = '707021'
    #cmd = 'sudo -S trivy clean --all'
   #call('echo {} | sudo -S {}'.format(pwd, cmd), shell=True)
    updateDB = subprocess.run(['trivy', 'image', '--download-db-only'], stdout=subprocess.PIPE)
    print(type(updateDB.stdout.decode('utf-8')))

    result = subprocess.run(['trivy', 'image', image_name], stdout=subprocess.PIPE)
    #print(type(result.stdout.decode('utf-8')))


    # process = subprocess.Popen('trivy image codewisdom/ts-news-service:0.0.4 -d' , shell=True, stdout=subprocess.PIPE)
    #print("Now in subprocess.Popen stage")
    # process.wait()
    #print("Now in process.wait()")

    value = str(result.stdout.decode('utf-8'))
    # cve_pattern = r'CVE-\d{4}-\d{4,7}'  # Matches CVE-YYYY-NNNNN (variable-length last part)
    pattern = r"(CVE-\d{4}-\d+)\s+(\bCRITICAL\b|\bHIGH\b|\bMEDIUM\b|\bLOW\b)?"
    matches = re.findall(pattern, value)
    print ([(cve, severity if severity else "UNKNOWN") for cve, severity in matches])
    # Extract all matches
    cve_list = re.findall(pattern, value)
    # Push to STIX doucment for each app_name
    createSTIX_vulnerability(app_name, cve_list)

    print("(((((((((((((((((((((((()))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) RAMI ")
    print("cve_list====", cve_list)
    print("(((((((((((((((((((((((()))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) RAMI ")

    # Print the result
    print(cve_list)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    # print("String value:", value)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")



    LOW_vlu = value.split('LOW:')
    low_value = LOW_vlu[1].split(',')

    MED_vlu = value.split('MEDIUM:')
    med_value = MED_vlu[1].split(',')

    HIGH_vlu = value.split('HIGH:')
    high_value = HIGH_vlu[1].split(',')

    CRITICAL_vlu = value.split('CRITICAL:')
    critical_value = CRITICAL_vlu[1].split(')')
    dictVuls = {
            "imageName": image_name,
            "LOW": low_value[0],
            "MEDIUM": med_value[0],
            "HIGH": high_value[0],
            "CRITICAL": critical_value[0]
    }



    print("*******************************************************************************************************")
    print("dictVuls========", dictVuls)
    print("*******************************************************************************************************")

    with open('assessment.txt', 'a') as file:
        file.write(json.dumps(dictVuls)+"\n")
    #print(dictVuls)
    print(">>>>>>>>> (START) <<<<<<<<< performance measurement for image scanning for image:", image_name)
    print(">>>>>>>>> (RESULT-start) <<<<<<<<< start", start)
    print(">>>>>>>>> (END) <<<<<<<<< performance measurement for image scanning for image:", image_name)


    return dictVuls

@app.route('/getVulnerabilityData', methods=['GET'])
def getVulnerabilityData():
    image_name = request.args.get('imagename')
    Vulnerabilitydata = "Not found"
    with open(r'assessment.txt', 'r') as fp:
        # read all lines using readline()
        lines = fp.readlines()
        for r in lines:
            if r.find(image_name) != -1:
                Vulnerabilitydata = r

    if Vulnerabilitydata != "Not found":
        try:
            dictVuls = {
                "LOW": Vulnerabilitydata.split("\"LOW\":")[1].split("\",")[0].split(" \" ")[1],
                "MEDIUM": Vulnerabilitydata.split("\"MEDIUM\":")[1].split("\",")[0].split(" \" ")[1],
                "HIGH": Vulnerabilitydata.split("\"HIGH\":")[1].split("\",")[0].split(" \" ")[1],
                "CRITICAL": Vulnerabilitydata.split("\"CRITICAL\":")[1].split("\",")[0].split(" \" ")[1].split("\"}\n")[
                    0]
            }
            print("Found the image >> return dictVuls")
            return dictVuls
        except ZeroDivisionError:
            print("Cannot dp dictVuls={}. Here is the default assigned value")
            return None
    else:
        print("Found the image >> return default message")
        return Vulnerabilitydata



    #print(dictVuls)


@app.route('/stix', methods=['POST', 'GET'])
def createSTIX():
    # parameters than have tp be send
    trustscore = request.args.get('trustscore')
    maliciousServiceName = request.args.get('maliciousservice')
    maliciousServiceX509 = request.args.get('X509')
    serviceNames = request.args.get('serviceNames')
    current_timeFirstSeen = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    returnMsg = "No STIX get generated"
    print("trustscore==",trustscore)
    if float(trustscore) > 0.0:
        returnMsg = "Yes a STIX document has generated!"
        if not os.path.exists("./" + maliciousServiceName + "/" + trustscore):
            os.makedirs("./" + maliciousServiceName + "/" + trustscore)

        # Write to the history file for the malicious Service
        f = './' + maliciousServiceName + '/history.csv'
        checkifHeaderneedsToBeAdded = False if os.path.isfile(f) else True
        with open(f, mode='a') as file:
            victims_writer = csv.writer(file, delimiter=',', lineterminator='\n', quotechar='"',
                                        quoting=csv.QUOTE_MINIMAL)
            if checkifHeaderneedsToBeAdded:
                victims_writer.writerow(['vitimServiceName', 'currentTimeFirstSeen', 'trustscore'])
            victims_writer.writerow([serviceNames, current_timeFirstSeen, trustscore])

        # Read for the hisotry for the maliciousService
        data_ = read_csv(f)
        vitimServiceNameList = data_['vitimServiceName'].tolist()
        currentTimeFirstSeenList = data_['currentTimeFirstSeen'].tolist()

        print("vitimServiceNameList:", vitimServiceNameList)
        print("currentTimeFirstSeenList:", currentTimeFirstSeenList)

        fs = FileSystemStore("./" + maliciousServiceName + "/" + trustscore)
        bundle = Bundle()

        last_timeSeenit = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        firstServiceSawIt = ""
        count = 0
        identitylist = []

        # dateinSec = current_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        # print("Date:",dateinSec[:-3])
        for x in range(len(vitimServiceNameList)):
            count = count +1
            tempdate = datetime.strptime(currentTimeFirstSeenList[x], '%Y-%m-%dT%H:%M:%S.%fZ')
            current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            if vitimServiceNameList.count(vitimServiceNameList[x]) > 1:
                # Bug fix it later print("duplicated service")
                identity_service = Identity(
                    created=tempdate,
                    modified=tempdate,
                    name=vitimServiceNameList[x],
                    identity_class="system",
                    spec_version="2.1",
                    type="identity"
                )
                identitylist.append(identity_service["id"])
                bundle = Bundle(
                    objects=[identity_service])
                fs.add(bundle)
            else:
                print("New vitim service")
                identity_service = Identity(
                    created=tempdate,
                    modified=tempdate,
                     name= vitimServiceNameList[x],
                     identity_class="system",
                       spec_version="2.1",
                    type="identity"
                  )
                identitylist.append(identity_service["id"])
                bundle = Bundle(
                      objects=[identity_service])
                fs.add(bundle)



            if x == 0:
                current_timeFirstSeen = current_time
                firstServiceSawIt = identity_service["id"]
                tempdate = datetime.strptime(currentTimeFirstSeenList[0], '%Y-%m-%dT%H:%M:%S.%fZ')
                tempdateLastseen = datetime.strptime(currentTimeFirstSeenList[len(vitimServiceNameList)-1], '%Y-%m-%dT%H:%M:%S.%fZ')
                current_timeFirstSeen = tempdate
                last_timeSeenit = tempdateLastseen
                indicator = Indicator(
                    type="indicator",
                    created_by_ref=identity_service["id"],
                    name=maliciousServiceName + " service is acting suspiciously",
                    description=maliciousServiceName+ " service trust metric reached "+ trustscore + "%",
                    indicator_types=["anomalous-activity"],
                    #pattern="[x509-certificate:serial_number = "+ maliciousServiceX509+ "]",
                    pattern_type="Unauthorized Access Attempts as Practiced by Adversary Service, " + maliciousServiceName ,
                    spec_version="2.1",
                    created=tempdate,
                    modified=tempdateLastseen,
                    valid_from=tempdate,
                    valid_until=tempdate + relativedelta(months=2)
                )
                bundle = Bundle(
                    objects=[indicator])
                fs.add(bundle)
            if count == len(serviceNames):
                last_timeSeenit = current_time

        counter = Counter(vitimServiceNameList)
        keys_ = counter.keys()
        countofVitimServics = len(keys_)

        sighting = Sighting(
            created_by_ref=firstServiceSawIt,
            created=current_timeFirstSeen,
            modified=last_timeSeenit,
            first_seen=current_timeFirstSeen,
            last_seen=last_timeSeenit,
            count=countofVitimServics,
            sighting_of_ref=indicator["id"],
            where_sighted_refs=identitylist,
            spec_version="2.1",
            type="sighting"
        )
        bundle = Bundle(
            objects=[sighting])
        fs.add(bundle)



        attack_pattern = AttackPattern(
            type="attack-pattern",
            spec_version="2.1",
            created=current_timeFirstSeen,
            modified=current_timeFirstSeen,
            name="Unauthorized Access Attempts as Practiced by Adversary Service, " + maliciousServiceName ,
            description="Send unauthorized access requests to services through calling a service by its DNS name and different ports more than 1 times in 60 seconds to gain access",
            kill_chain_phases=[{"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "reconnaissance"}]
        )
        relationship1 = Relationship(indicator, 'indicates', attack_pattern)

        note = Note(
            type="note",
            spec_version="2.1",
            created=current_timeFirstSeen,
            modified=current_timeFirstSeen,
            object_refs=[attack_pattern["id"]],
            abstract="Malicious service trust score",
            content="Trust score="+trustscore + "%",
        )

        relationship2 = Relationship(attack_pattern, 'creates', note)

        bundle = Bundle(
            objects=[attack_pattern,
                     relationship1, note, relationship2])
        fs.add(bundle)
    return returnMsg

def createSTIX_vulnerability(app_name, cve_list):
    stix_objects = []



    # Create STIX Vulnerability objects and relationships

    vuln = Vulnerability(
    id=f"vulnerability--{uuid.uuid4()}",
    name="All CVEs in "+app_name,
    description=f"Details about all CVEs in microservice.",
    created=datetime.utcnow().isoformat() + "Z",
    modified=datetime.utcnow().isoformat() + "Z",
    external_references=[{
        "source_name": "cve",
        "external_id": cve_list
     }]
        )
    stix_objects.append(vuln)




    # Create a STIX bundle
    stix_bundle = Bundle(objects=stix_objects)

    # Save to a JSON file
    with open(app_name+".json", "w") as f:
        f.write(stix_bundle.serialize(pretty=True))

    print("STIX JSON file for microservice", app_name,  ".json' created successfully!")
    # parameters than have tp be send



    return "STIX JSON file for microservice", app_name,  ".json' created successfully!"
def find_TM (ServiceName):
    try:
        subfolders = [f.name for f in os.scandir("./" + ServiceName) if f.is_dir()]
        TM_score = min(subfolders)
    except FileNotFoundError:
        print("ERROR: FileNotFoundError >>>>> TM for this: ", ServiceName , " can not be found. 100 is returned")
        TM_score = "100"
    return TM_score

def taxii_pull(caller_ms , target_ms):
    print("taxii_pull() >>>>>> called")
    print("caller_ms() >>>>>> called", caller_ms)
    path = "/app"

    if os.path.exists(path):
        print(f"✅ Folder exists: {path}")
        print("Contents:", os.listdir(path))  # List the folder contents
    else:
        print(f"❌ Folder does not exist: {path}")
    python_objects = []
    path3 = ""
    path = path + "/"+ target_ms
    if os.path.exists(path):
        print(f"✅✅✅ Folder for target_ms exists: {path}")
        print("Contents:", os.listdir(path))  # List the folder contents
    else:
        print(f"❌❌❌ Folder does not exist for target_ms: {path}")
    print("path===", path)
    print("s.path.exists(path)===", os.path.exists(path))
    if os.path.exists(path):
        subfolders = [ f.name for f in os.scandir("./"+target_ms) if f.is_dir() ]
        min_score = min (subfolders)
        fs = FileSystemStore("./"+target_ms + "/" + min_score)
        subfoldersSTIX = [ f.name for f in os.scandir("./"+target_ms +"/" +min_score) if f.is_dir() ]
        path = path + "/" + min_score + "/"
        if os.path.exists(path):
            for x in subfoldersSTIX:
                subfoldersSTIXObjects = [f.name for f in os.scandir("./" + target_ms + "/" + min_score+ "/"+ x) if f.is_dir()]
                for y in subfoldersSTIXObjects:
                    path2 = path  + x +"/" + y
                    sub_subfoldersSTIXObjects = [ff.name for ff in
                                             os.scandir(path2) ]
                    #txt_files.append(path2 + sub_subfoldersSTIXObjects.)
                    for z in sub_subfoldersSTIXObjects:
                        print("z=",z)
                        path3 = path2 + "/" + z
                        print("path3===", path3)
                        f = open(path3)
                        temp = json.load(f)
                        python_objects.append(temp)
    print("python_objects===", python_objects)
    with open("combined.json", "w") as f:
        json.dump(python_objects, f, indent=4)
    f = open('combined.json')
    data = json.load(f)
    print("data >>>>>>", str(data))
    os.remove("combined.json")

    return data

@app.route('/hasValidRegistraion/<string:caller_ms>/<string:target_ms>', methods=['GET'])
def hasValidRegistraion(caller_ms , target_ms):
    hasValidRegistraion = "1" # no access 2: yes give access
    print("request.url=",request.url )
    print("caller_ms=", caller_ms)
    print("target_ms=", target_ms)
    parsed_url = urlparse(request.url)
    print("request.url=", request.url)
    path_segments = parsed_url.path.strip('/').split('/')
    print(path_segments)
    print("request.base_url=", request.base_url)
    print("request.host_url=", request.host_url)
    print("request.root_url=", request.root_url)
    print("find_TM")
    TM_callerServiceName= find_TM(caller_ms)
    # bring TM_acceptable for caller_ms
    TM_acceptable = 100
    TM_acceptable = bringTM_acceptable(caller_ms)


    # find the current TM
    print("type=", type(find_TM(caller_ms)) )
    print("TM_callerServiceName======", TM_callerServiceName)
    print("TM_acceptable======", TM_acceptable)

    print("float(TM_callerServiceName) >= float(TM_acceptable):", float(TM_callerServiceName) >= float(TM_acceptable))
    if float(TM_callerServiceName) >= float(TM_acceptable):
        hasValidRegistraion = "2"
        print("for this TM_callerServiceName:", TM_callerServiceName, " has full ACCESS to access STIX documents. ")
        print("Keep the callerService name from the subscription list")
        print("microservices_names list []:", microservices_names)
        print("taxii_pulled")
        print("hasValidRegistraion Allow access====", hasValidRegistraion)

        return hasValidRegistraion + "/" + str(taxii_pull(caller_ms, target_ms))

    else:
        hasValidRegistraion = "1"
        print("for this TM_callerServiceName:", TM_callerServiceName, " has to DENIED to access STIX documents should be shared. ")
        print("Remove the callerService name from the subscription list")
        microservices_names.remove(caller_ms)
        print("microservices_names list []:", microservices_names)
        print("hasValidRegistraion DENY access====", hasValidRegistraion)
        return hasValidRegistraion

def bringTM_acceptable (caller_ms):
    s_label = "null"
    TM_acceptable = 0
    print("------------------------ print all configmaps ------------------------------------------")
    # Go get caller_ms labels
    if (flag):
        config.load_kube_config()
    else:
        config.load_incluster_config()
    v1 = client.CoreV1Api()
    v2 = client.AppsV1Api()
    try:
        deployment = v2.read_namespaced_deployment(name=caller_ms, namespace="default")
        labels = deployment.metadata.labels
        if labels:
            print(f"Labels for deployment '{caller_ms}':")
            for key, value in labels.items():
                if key == "s":
                    s_label = value

                print(f"  {key}: {value}")
        else:
            print(f"No labels found for deployment '{caller_ms}'.")
    except client.exceptions.ApiException as e:
        if e.status == 404:
            print(f"Deployment '{caller_ms}' not found in the namespace.")
        else:
            print(f"An error occurred: {e}")


    configmaps = v1.list_namespaced_config_map("default")
    # Print the names of the ConfigMaps
    for cm in configmaps.items:
        print(cm.metadata.name)
        if cm.metadata.name == ("configmap-" + s_label.lower()):
            print("found a configmap matched")
            for key, value in cm.data.items():
                if key == "T":
                    TM_acceptable = value
                    print("Here is the founded TM_acceptable=", TM_acceptable)

                    return TM_acceptable
        else:
            print("no matched configmap founded.")
    return TM_acceptable



    # find the T in the founded configmap > return it






@app.route('/victimeslist',  methods=['POST', 'GET'])
def victimeslist():
    maliciousServiceName = request.args.get('maliciousservice')
    trustscore = request.args.get('trustscore')
    print("maliciousServiceName:", maliciousServiceName)
    print("trustscore:", trustscore)

    # Go look for the Dir names: maliciousServiceName/trustscore/sighting
    path = "./" + maliciousServiceName
    if os.path.exists(path):
        print("Found the dir:"+ maliciousServiceName)
        if os.path.exists(path + "/" + trustscore):
            print("Found the sub-dir:" + path + "/" + trustscore)
            if os.path.exists(path + "/" + trustscore + "/sighting"):
                print("Found the sub-dir-dri:" + path + "/" + trustscore + "/sighting")
                sighting_names = os.listdir("./" + maliciousServiceName + "/" + trustscore + "/sighting")
                for x in sighting_names:
                    print(x)
                    filename = os.listdir("./" + maliciousServiceName + "/" + trustscore + "/sighting/"+x)
                    print(filename)
                    file_name_temp = str("./" + maliciousServiceName + "/" + trustscore + "/sighting/"+str(x) + "/" + str(filename[0]))
                    print(file_name_temp)

                    with open(file_name_temp, 'r') as f:
                        data = json.load(f)
                        name = data["where_sighted_refs"]
                        print(name)


    # Read the JSON
    # Read the JSON then find the values under: where_sighted_refs as List named X
        # For loop the X list
            # Then look for a dir names as maliciousServiceName/trustscore/identity/X[i]/
            # Then read the JSON file inside the Dir
                # Then look for a field name called "name"

    return returnJSONAllObjects

if __name__ == "__main__":
    start = time.time()
    # get all microseorcie names on start up
    write_trusted_microservices_names()
    list_and_sacn_all_images()
    end = time.time()
    print(">>>>>>>>> (TIS Processing time) RESULT-end) <<<<<<<<< start", start)
    print(">>>>>>>>> (TIS Processing time) RESULT-end) <<<<<<<<< end", end)
    print(">>>>>>>>> (RESULT) <<<<<<<<< end - start: ", (end - start))

    app.run(host="0.0.0.0", port=9708)
