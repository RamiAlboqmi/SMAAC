# minikube start --cpus=9 --memory 40906 --disk-size 200g
import datetime
import json
import logging
import os
import pathlib
import string
import sys
from typing import List
from uuid import uuid4
import argparse
import time

from ilcli import Command
import yaml
import pandas as pd
from kubernetes import client, config

import trestle.oscal.catalog as oscat
import trestle.oscal.common as oscommon
import trestle.oscal.profile as ospro
import trestle.oscal.component as oscom
import trestle.oscal.ssp as sp

from trestle.core.repository import Repository
from kubernetes import config, dynamic
from kubernetes.client import api_client
#from pathlib import Path

import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# using calendar module
# using time module
import calendar;
import time;


flag = True

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))

import sys
import ruamel.yaml


def createOSCAL2(input_xls: pathlib.Path) -> int:

    print ("sp.Base.schema()===",sp.Base.schema())
    # Get timestamp value as string
    gmt = time.gmtime()
    ts = calendar.timegm(gmt)
    version = str(ts)
    print("timestamp:-", ts)
    print("Type timestamp:-", type(ts))

    # Get the file path
    print("Get excel file name:", input_xls)
    path1 = pathlib.Path(input_xls)
    temp_output_directory = "GRC_requirements"
    temp_output_directory_catalog = "GRC_requirements/catalog"
    temp_output_directory_profile = "GRC_requirements/profile"
    temp_output_directory_ssp = "GRC_requirements/ssp"
    temp_output_directory_comp = "GRC_requirements/comp"


    output_directory = path1 = pathlib.Path(temp_output_directory)
    output_directory_catalog = path1 = pathlib.Path(temp_output_directory_catalog)
    output_directory_profile = path1 = pathlib.Path(temp_output_directory_profile)
    output_directory_ssp = path1 = pathlib.Path(temp_output_directory_ssp)
    output_directory_comp = path1 = pathlib.Path(temp_output_directory_comp)


    print("I will save do the process on this Dir to access the excel file:", type(path1))

    # Set the profile path
    excel_handler = pd.ExcelFile(input_xls)

    # read each line in the sheet and inner values
    df = None
    for key in excel_handler.sheet_names:
        # print("I'm searing each sheet in the excel file now")
        # If there is a sheet that has a control as a string, do the OSCAL
        if 'controls' in str(key).lower():
            sheet_name = key
    df = pd.read_excel(input_xls, sheet_name=sheet_name, header=0, dtype=str)

    for _, row in df.iterrows():
        ss = row['SS type']

        # create catlogs
        catlogs: List[oscat.Control] = []
        control = oscat.Control(id=f'control-{ss}', title=row['Title'])
        control.parts = [oscommon.Part(name='PP', prose=row['PP'])]
        catlogs.append(control)
        cat_metadata = oscommon.Metadata(
            **{
                'title': f'CaC Controls version {ss} catalog.',
                'last-modified': datetime.datetime.now().astimezone(),
                'version': version,
                'oscal-version': '1.0.4'
            }
        )
        cat = oscat.Catalog(uuid=str(uuid4()), metadata=cat_metadata, controls=catlogs)
        catalog_path: pathlib.Path = output_directory_catalog / f'{ss}_catalog.yaml'
        cat.oscal_write(catalog_path)

        # create profiles
        profile_path: pathlib.Path = output_directory_profile / f'{ss}_profile.yaml'
        profile1 = ospro.Profile(
            uuid=str(uuid4()),
            metadata=oscommon.Metadata(
                **{
                    'title': f'Profile-for-services-that-has-s= {ss}',
                    'version': version,
                    'oscal-version': '1.0.4',
                    'last-modified': datetime.datetime.now().astimezone()
                }
            ),
            imports=[ospro.Import(href=catalog_path.name)]
        )
        grp1: List[str] = []
        cid = f'control-{ss}'
        grp1.append(cid)
        write_profile(profile1, grp1, profile_path)
        fips: string
        fips = "fips-199-moderate"
        # create SSP

        # Check if the SS foudn in any servcie, create the SS. At the end, you should see: P1, P3, and P5 have Operaiton state
        # P2 and P4 have D state


        print("The S", {ss}, "status=", getDeply(str({ss})))

        if  getDeply(str({ss})):
            print("in SSP if to do the CM creation for:", {ss} )
            ssp_path: pathlib.Path = output_directory_ssp / f'{ss}_ssp.yaml'
            operational = 'operational'

            # Create SSP
            ssp = sp.SystemSecurityPlan(
                uuid=str(uuid4()),
                metadata=oscommon.Metadata(
                    **{
                        'title': f'SSP-for-profiles-that-has-s= {ss}',
                        'version': version,
                        'oscal-version': '1.0.4',
                        'last-modified': datetime.datetime.now().astimezone()
                    }
                ),
                import_profile=sp.ImportProfile(href=profile_path.name),
                control_implementation=sp.ControlImplementation(
                    description="ControlImplementation-1",
                    # implemented-requirements
                    implemented_requirements=[sp.ImplementedRequirement(
                        uuid=str(uuid4()),
                        control_id="control-1.1",
                        # "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: game-demo\ndata:\n  # property-like keys; each key maps to a simple value\n  player_initial_lives: \"3\"\n  ui_properties_file_name: \"user-interface.properties\"\n\n  # file-like keys\n  game.properties: |\n    enemy.types=aliens,monsters\n    player.maximum-lives=5    \n  user-interface.properties: |\n    color.good=purple\n    color.bad=yellow\n    allow.textmode=true"
                    )],
                    #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

                ),
                system_implementation=sp.SystemImplementation(
                    users=[],
                    components=[],

                    #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

                ),
                system_characteristics=sp.SystemCharacteristics(
                    system_ids=[sp.common.SystemId(
                        id='csp_iaas_system'
                    )],
                    description="description",
                    system_name="system_name-",
                    security_sensitivity_level="low",
                    system_information=sp.SystemInformation(
                        information_types=[sp.InformationType(
                            title="title",
                            description="InformationTypedescription",
                            categorizations=[sp.Categorization(
                                system="https://doi.org/10.6028/NIST.SP.800-60v2r1"
                                       "",
                                information_type_ids=["c.3.5.8"]
                            )],
                            confidentiality_impact=sp.ConfidentialityImpact(
                                base=sp.Base(
                                    __root__='fips_199_moderate',
                                ),
                            ),
                            integrity_impact=sp.IntegrityImpact(
                                base=sp.Base(
                                    __root__='fips_199_moderate',
                                ),
                            ),
                            availability_impact=sp.AvailabilityImpact(
                                base=sp.Base(
                                    __root__='fips_199_moderate',
                                ),
                            ),
                        )],

                    ),
                    status=sp.Status1(state=sp.State.operational),
                    authorization_boundary=sp.AuthorizationBoundary(
                        description='description'
                    ),

                    security_impact_level=sp.SecurityImpactLevel(
                        security_objective_confidentiality='fips-199-low',
                        security_objective_integrity='fips-199-low',
                        security_objective_availability='fips-199-low',
                    )
                    #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

                ),

            )
            #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]
            # Create Componeont
            list_ = list(row['PP'].split(","))
            print("list=========*****:", list_)
            if any("M:" in item for item in list_):
                # In this ability, certain requirements can be pushed, and to distinguish a REST requirement from gRPC, M: means the method of sending the price in gRPC as described in the research
               print("gRPC req >>>>>", list_)
            else:
                print("It is a REST.")
            temp_string = ""
            data_dict = dict()

            for item in list_:
                list_2 = list(item.split(":"))
                print("list_2====", list_2)
                data_dict[list_2[0]] = list_2[1]
            configmap_value = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + f'configmap-{ss}'.lower() \
                              + "\ndata:\n " + f"{data_dict}"
            print("configmap_value====", configmap_value)
            compeont1 = oscom.ComponentDefinition(
                uuid=str(uuid4()),
                metadata=oscommon.Metadata(
                    **{
                        'title': 'CaC ComponentDefinition 1',
                        'version': version,
                        'oscal-version': '1.0.4',
                        'last-modified': datetime.datetime.now().astimezone()
                    }
                ),
                components=[oscom.DefinedComponent(
                    uuid=str(uuid4()),
                    title="components-1",
                    type="service",
                    description="components-1-description",
                    control_implementations=[oscom.ControlImplementation(
                        uuid=str(uuid4()),
                        description="ControlImplementation-1",
                        source=profile_path.name,
                        implemented_requirements=[oscom.ImplementedRequirement(
                            uuid=str(uuid4()),
                            description="ControlImplementation-1",
                            control_id="control-1.1",
                            # "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: game-demo\ndata:\n  # property-like keys; each key maps to a simple value\n  player_initial_lives: \"3\"\n  ui_properties_file_name: \"user-interface.properties\"\n\n  # file-like keys\n  game.properties: |\n    enemy.types=aliens,monsters\n    player.maximum-lives=5    \n  user-interface.properties: |\n    color.good=purple\n    color.bad=yellow\n    allow.textmode=true"
                            configmap=configmap_value
                        )],
                        #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

                    )],
                )],
                #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]
            )
            configmap_manifest = {
                "kind": "ConfigMap",
                "apiVersion": "v1",
                "metadata": {
                    "name": f'configmap-{ss}'.lower(),
                    "labels": {
                        "s": row['SS type']
                    }
                },
                "data": data_dict,
            }
            if (flag):
                client = dynamic.DynamicClient(
                    api_client.ApiClient(configuration=config.load_kube_config())
                )
            else:
                client = dynamic.DynamicClient(
                    api_client.ApiClient(configuration=config.load_incluster_config())
                )

            ## Add ConfigMap to K8s -----------------------------------------------


            #  "G" : "50" ,"P" : "60" ,"U" : "50" ,"D" : "40" ,"O" : "50"
            # result_data = json.loads("temp_string")
            # print("############### The converted dictionary result_data is  : " + str(result_data))

            # print result
            # print("The converted dictionary result_data is  : " + str(result_data))

            # fetching the configmap api
            api = client.resources.get(api_version="v1", kind="ConfigMap")
            # Creating configmap `test-configmap` in the `default` namespace

            # Creating configmap `test-configmap` in the `default` namespace
            print("configmap_manifest=====", configmap_manifest)
            api.create(body=configmap_manifest, namespace="default")

            comp_path: pathlib.Path = output_directory_comp / f'{ss}_comp.yaml'
            write_component(compeont1, [], comp_path)

    else:
        ssp_path: pathlib.Path = output_directory_ssp / f'{ss}_ssp.yaml'
        operational = 'operational'

        # Create SSP
        ssp = sp.SystemSecurityPlan(
            uuid=str(uuid4()),
            metadata=oscommon.Metadata(
                **{
                    'title': f'SSP-for-profiles-that-has-s= {ss}',
                    'version': version,
                    'oscal-version': '1.0.4',
                    'last-modified': datetime.datetime.now().astimezone()
                }
            ),
            import_profile=sp.ImportProfile(href=profile_path.name),
            control_implementation=sp.ControlImplementation(
                description="ControlImplementation-1",
                # implemented-requirements
                implemented_requirements=[sp.ImplementedRequirement(
                    uuid=str(uuid4()),
                    control_id="control-1.1",
                    # "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: game-demo\ndata:\n  # property-like keys; each key maps to a simple value\n  player_initial_lives: \"3\"\n  ui_properties_file_name: \"user-interface.properties\"\n\n  # file-like keys\n  game.properties: |\n    enemy.types=aliens,monsters\n    player.maximum-lives=5    \n  user-interface.properties: |\n    color.good=purple\n    color.bad=yellow\n    allow.textmode=true"
                )],
                #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

            ),
            system_implementation=sp.SystemImplementation(
                users=[],
                components=[],

                #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

            ),
            system_characteristics=sp.SystemCharacteristics(
                system_ids=[sp.common.SystemId(
                    id='csp_iaas_system'
                )],
                description="description",
                system_name="system_name-",
                security_sensitivity_level="low",
                system_information=sp.SystemInformation(
                    information_types=[sp.InformationType(
                        title="title",
                        description="InformationTypedescription",
                        categorizations=[sp.Categorization(
                            system="https://doi.org/10.6028/NIST.SP.800-60v2r1"
                                   "",
                            information_type_ids=["c.3.5.8"]
                        )],
                        confidentiality_impact=sp.ConfidentialityImpact(
                            base=sp.Base(
                                __root__='fips_199_moderate',
                            ),
                        ),
                        integrity_impact=sp.IntegrityImpact(
                            base=sp.Base(
                                __root__='fips_199_moderate',
                            ),
                        ),
                        availability_impact=sp.AvailabilityImpact(
                            base=sp.Base(
                                __root__='fips_199_moderate',
                            ),
                        ),
                    )],

                ),
                status=sp.Status1(state=sp.State.disposition),
                authorization_boundary=sp.AuthorizationBoundary(
                    description='description'
                ),

                security_impact_level=sp.SecurityImpactLevel(
                    security_objective_confidentiality='fips-199-low',
                    security_objective_integrity='fips-199-low',
                    security_objective_availability='fips-199-low',
                )
                #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

            ),

        )
        #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

        grp1: List[str] = []
        cid = f'profile-{ss}'
        grp1.append(cid)
        write_ssp(ssp, grp1, ssp_path)




def createOSCAL(input_xls: pathlib.Path) -> int:

    # Get timestamp value as string
    gmt = time.gmtime()
    ts = calendar.timegm(gmt)
    version = str(ts)
    print("timestamp:-", ts)
    print("Type timestamp:-", type(ts))

    # Get the file path
    print("Get excel file name:", input_xls)
    path1 = pathlib.Path(input_xls)
    temp_output_directory = "GRC_requirements"
    output_directory = path1 = pathlib.Path(temp_output_directory)
    print("I will save do the process on this Dir to access the excel file:", type(path1))

    # Set the profile path
    excel_handler = pd.ExcelFile(input_xls)
    profile_path: pathlib.Path = output_directory / f'{version}_profile.yaml'

    # read each line in the sheet and inner values
    df = None
    for key in excel_handler.sheet_names:
        # print("I'm searing each sheet in the excel file now")
        # If there is a sheet that has a control as a string, do the OSCAL
        if 'controls' in str(key).lower():
            sheet_name = key

    print("now I'm reading the content of the sheet:",sheet_name )
    df = pd.read_excel(input_xls, sheet_name=sheet_name, header=0, dtype=str)


    # for profiles / implementation groups
    grp1: List[str] = []

    grp2: List[str] = []
    grp3: List[str] = []

    print("79- I just created an empty OSCAL catalog (contorl) obj for next processes")
    # Create a catlog object
    catlogs: List[oscat.Control] = []

    print("83- I just created an empty control obj for next processes")
    # Create a catlog object
    control = None

    print("87- I just created an empty subcontrols obj for next processes")
    subcontrols = None
    control_prose = ''

    # Get a control colum: CaC Control 1st column
    control_key = 'CaC Control'

    # Get a control colum: CaC Safeguard - 2nd column
    CaC_Safeguard = 'CaC Safeguard'

    for _, row in df.iterrows():
        print("-------------------------------- 98 - I'm in the loop now ---------------------------")
        print("I'm not reading each line in the sheet. The current row is:",row)
        # do search each row in the column: CaC Control
        if not pd.isna(row[control_key]):
            print("I'm now dealing with the row column (cell) for CaC Control. The current row:",row[control_key])
            # do search each row in the column: CaC Safeguard
            if pd.isna(row[CaC_Safeguard]):
                # For the for loop until it is none
                control = oscat.Control(id=f'control-{row[control_key].strip()}', title=row['Title'])
                print("oscat.Control=====", oscat.Control)
                # Set the subcontrols null for next process.
                subcontrols: List[oscat.Control] = []

                print("----------------- Create catalog if statement inside the loop t ocreate: [Description],  ------------------")
                print("I'm now dealing with the row column (cell) for CaC Safeguard. The current row:", row[CaC_Safeguard])

                if control is not None:
                    print("I'm now checking if the oscat.Control is not empty. Here is the control now: ",control)

                    control.controls = subcontrols
                    print("I'm now checking controls inside each oscat.Control as control.controls which now equals: ",control.controls)


                    control.parts = [oscommon.Part(name='Description', prose=row['PP'])]
                    print("I'm now checking controls inside each oscat. control.parts = ",control.parts)

                    # Set a catlog for the control

                    catlogs.append(control)
                    print("I just appended the contorl to the catalog. Catlogs=",catlogs)




            else:
                print("----------------- Create catalog if statement inside the loop ------------------")
                # if it has both a CIS Control entry and sub-control entry it is a sub-control
                # Rami Description
                part = oscommon.Part(name='purchasingPoints', prose=row['PP'])
                cid = f'control-{row[CaC_Safeguard].strip()}'
                print("row=========",row['PP'])
                print("row=========type",type(row['PP']))
                # Rami  Asset Type + Title
                subcont = oscat.Control(id=cid, title=row['Title'], class_=row['SS type'], parts=[part])
                subcontrols.append(subcont)

                grp1.append(cid)
                # component Definition
                uuid_=str(uuid4())

                list_ = list(row['PP'].split(","))
                print("list=========*****:", list_)
                temp_string = ""
                data_dict = dict()

                for item in list_:
                    list_2 = list(item.split(":"))
                    print("list_2====",list_2)
                    data_dict[list_2[0]] = list_2[1]
                   # temp_string = temp_string + f"\n  {list_2[0]}: \"{list_2[1]}\""
                    #if list_2[1] != "":
                     #   temp_string = temp_string + f"\"{list_2[0]}\" : \"{list_2[1]}\" ,"

                configmap_value = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + version + uuid_ + "\ndata:\n " + f"{data_dict}"
                compeont1 = oscom.ComponentDefinition(
                    uuid=uuid_,
                    metadata=oscommon.Metadata(
                        **{
                            'title': 'CaC ComponentDefinition 1',
                            'version': version,
                            'oscal-version': '1.0.4',
                            'last-modified': datetime.datetime.now().astimezone()
                        }
                    ),
                    components=[oscom.DefinedComponent(
                        uuid=str(uuid4()),
                        title="components-1",
                        type="service",
                        description="components-1-description",
                        control_implementations=[oscom.ControlImplementation(
                            uuid=str(uuid4()),
                            description="ControlImplementation-1",
                            source=profile_path.name,
                            implemented_requirements=[oscom.ImplementedRequirement(
                                uuid=str(uuid4()),
                                description="ControlImplementation-1",
                                control_id="control-1.1",
                                # "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: game-demo\ndata:\n  # property-like keys; each key maps to a simple value\n  player_initial_lives: \"3\"\n  ui_properties_file_name: \"user-interface.properties\"\n\n  # file-like keys\n  game.properties: |\n    enemy.types=aliens,monsters\n    player.maximum-lives=5    \n  user-interface.properties: |\n    color.good=purple\n    color.bad=yellow\n    allow.textmode=true"
                                configmap=configmap_value
                            )],
                            #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]

                        )],
                    )],
                    #  control-implementations= [oscom.]ControlImplementation(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap")]
                )
                ## Add ConfigMap to K8s -----------------------------------------------


                if (flag):

                    client = dynamic.DynamicClient(
                        api_client.ApiClient(configuration=config.load_kube_config())
                    )
                else:
                    client = dynamic.DynamicClient(
                        api_client.ApiClient(configuration=config.load_incluster_config())
                    )

                print("############### data_dict ###############")
                print(json.dumps(data_dict, indent=4))

                #  "G" : "50" ,"P" : "60" ,"U" : "50" ,"D" : "40" ,"O" : "50"
               # result_data = json.loads("temp_string")
                #print("############### The converted dictionary result_data is  : " + str(result_data))

                # print result
                # print("The converted dictionary result_data is  : " + str(result_data))

                # fetching the configmap api
                api = client.resources.get(api_version="v1", kind="ConfigMap")
                # Creating configmap `test-configmap` in the `default` namespace
                configmap_name = version + uuid_
                print("row['SS type']=======",row['SS type'])
                configmap_manifest = {
                    "kind": "ConfigMap",
                    "apiVersion": "v1",
                    "metadata": {
                        "name": configmap_name,
                        "labels": {
                            "s": row['SS type']
                        }
                    },
                    "data": data_dict,
                }

                # Creating configmap `test-configmap` in the `default` namespace

                configmap = api.create(body=configmap_manifest, namespace="default")

                print("\n[INFO] configmap" +  version + uuid_ + " created\n")

                configmap_list = api.get(
                    name=configmap_name, namespace="default", label_selector="foo=bar"
                )

                print("NAME:\n%s\n" % (configmap_list.metadata.name))
                print("DATA:\n%s\n" % (configmap_list.data))


                ## -------------------------------------------------------------------

                comp_path: pathlib.Path = output_directory / f'{version}_{uuid_}_comp.yaml'
                write_component(compeont1, [], comp_path)
                # Rami IG1
                # now add it to corresponding profile / implementation group
                # if not pd.isna(row['needassessment']):
                #     print("grp1:", cid )
                #     grp1.append(cid)
                # # Rami IG2
                # if not pd.isna(row['na']):
                #     print("grp2:", cid )
                #     grp2.append(cid)
                #
                # # Rami IG3
                # if not pd.isna(row['noissue']):
                #     print("grp3:", cid )
                #     grp3.append(cid)
        else:
            # if it has no CIS Control entry but it does have title field it is prose for the main control
            # Rami Title
            if not pd.isna(row['Title']):
                control_prose = row['Title']

    # need to add last one
    control.controls = subcontrols
    # Rami Description
    control.parts = [oscommon.Part(name='Description', prose=control_prose)]
    catlogs.append(control)

    cat_metadata = oscommon.Metadata(
        **{
            'title': f'CaC Controls version {version} catalog.',
            'last-modified': datetime.datetime.now().astimezone(),
            'version': version,
            'oscal-version': '1.0.4'
        }
    )

    cat = oscat.Catalog(uuid=str(uuid4()), metadata=cat_metadata, controls=catlogs)
    catalog_path: pathlib.Path = output_directory / f'{version}_catalog.yaml'

    print("PATH=",catalog_path)
    cat.oscal_write(catalog_path)


    ########################## Profile ###################################
    profile1 = ospro.Profile(
        uuid=str(uuid4()),
        metadata=oscommon.Metadata(
            **{
                'title': 'CaC Implementation Group 1',
                'version': version,
                'oscal-version': '1.0.4',
                'last-modified': datetime.datetime.now().astimezone()
            }
        ),
        imports=[ospro.Import(href=catalog_path.name)]
    )
    profile2 = ospro.Profile(
        uuid=str(uuid4()),
        metadata=oscommon.Metadata(
            **{
                'title': 'CaC Implementation Group 2',
                'version': version,
                'oscal-version': '1.0.4',
                'last-modified': datetime.datetime.now().astimezone()
            }
        ),
        imports=[ospro.Import(href=catalog_path.name)]
    )
    profile3 = ospro.Profile(
        uuid=str(uuid4()),
        metadata=oscommon.Metadata(
            **{
                'title': 'CaC Implementation Group 3',
                'version': version,
                'oscal-version': '1.0.4',
                'last-modified': datetime.datetime.now().astimezone()
            }
        ),
        imports=[ospro.Import(href=catalog_path.name)]
    )



    write_profile(profile1, grp1, profile_path)
    print(":::::::::::::::>>>profile_path:", profile_path)

   # profile_path: pathlib.Path = output_directory / f'CaC_version_{version}_profile_Implementation_Group_2.yaml'
   # write_profile(profile2, grp2, profile_path)

    # profile_path: pathlib.Path = output_directory / f'CaC_version_{version}_profile_Implementation_Group_3.yaml'
    # write_profile(profile3, grp3, profile_path)


   # implemented_requirements_ = oscom.ControlImplementation.implemented_requirements(uuid=str(uuid4()), source=str(uuid4()), description="ConfigMap"))




    # remove excel
    os.remove(input_xls)

def getDeply(s: string):
    print("in getDeply() method to check if MS=", s , " has a complaince requirnement.")
    # Configs can be set in Configuration class directly or using helper utility
    if (flag):
        config.load_kube_config()
    else:
        config.load_incluster_config()

    bool = False
    v1 = client.CoreV1Api()
    #print("Listing pods with their IPs:")
    ret = v1.list_pod_for_all_namespaces(watch=False)
    v1_apps = client.AppsV1Api()
    deployments = v1_apps.list_deployment_for_all_namespaces(watch=False)
    # Print deployment names
    for i in deployments.items:
        print("metadata.name=====", i.metadata.name)
        print("metadata.labels=====", i.metadata.labels)

        if i.metadata.labels:
            for label_key, label_value in i.metadata.labels.items():
                print(f"  Label: {label_key} = {label_value}")
                print("label_key =='s'===", label_key =='s')
                print("label_key ==", label_key)
                print("label_key len ==", len(label_key))
                print("s len ==", len('s'))
                print("s===", s)
                print("s===len ()====", len(s))
                print("s===len (label_value)====", len(label_value))
                print(s == "{'"+label_value +"'}")

                if label_key =='s':
                    if s == "{'"+label_value +"'}":
                        print("Found")
                        print("label_value=====", label_value)
                        print("s=====", s)
                        print("metadata.name=====", i.metadata.name)
                        bool = True
                        return bool
                    else:
                        print("Not found")
                        bool = False
        else:
            print("  No labels found.")

        #print(i.metadata.labels.get('s'))
    return bool

def write_profile(profile: ospro.Profile, control_list: List[str], path: pathlib.Path):
    """Fill in control list and write the profile."""
    include_controls: List[str] = []
    selector = ospro.SelectControlById()
    selector.with_ids = control_list
    include_controls.append(selector)
    profile.imports[0].include_controls = include_controls

    profile.oscal_write(path)

def write_ssp(sec: sp.SystemSecurityPlan, profile_list: List[str], path: pathlib.Path):
    """Fill in control list and write the profile."""


    sec.oscal_write(path)


def write_component(componentdefinition: oscom.ComponentDefinition, control_list: List[str], path: pathlib.Path):
    """Fill in control list and write the profile."""
    include_controls: List[str] = []

    selector = ospro.SelectControlById()
    selector.with_ids = control_list
    include_controls.append(selector)
    #componentdefinition.imports[0].include_controls = include_controls
    componentdefinition.oscal_write(path)

    with open(path, 'r') as file:
        prime_service = yaml.safe_load(file)
    print("Print ----------- ")

    print(prime_service['component-definition'])
    print("22222 Print ----------- 2")

    print(prime_service['component-definition']['components'][0])
    dic = {}
    dic = prime_service['component-definition']['components'][0]['control-implementations'][0]['implemented-requirements'][0]['configmap']
    print(dic)







class OnMyWatch:


    # Set the directory on watch
    watchDirectory = "./Inbox"

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.watchDirectory, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Observer Stopped")

        self.observer.join()


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        start_time = time.time()

        if event.is_directory:
            return None

        elif event.event_type == 'created':
            # Event is created, you can process it now
            print("Watchdog received created event - % s." % event.src_path)
            print("Call createOSCAL() method")
            createOSCAL2(event.src_path)
        elif event.event_type == 'modified':
            # Event is modified, you can process it now
            print("Watchdog received modified event - % s." % event.src_path)

        end_time = time.time()
        Processing_time = (end_time - start_time) * 1000
        print(f"Processing Time: {Processing_time:.3f} ms")

if __name__ == '__main__':    # Creating a dynamic client


    watch = OnMyWatch()
    watch.run()
