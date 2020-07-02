#!/usr/bin/env python3

# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------
#
# Parts of code and comments contained in this file are taken from 
# the official Hyperledger Sawtooth documentation
# https://sawtooth.hyperledger.org/docs/core/releases/1.1.4/contents.html
# and from example projects from developer ``danintel'':
# https://github.com/danintel/sawtooth-cookiejar
#
'''
Command line interface for administration TF.
Parses command line arguments and passes to the AdministrationClient class
to process.
'''

import argparse
import logging
import os
import sys
import traceback
import cbor
import csv
import configparser
import properties_pb2
import policies_pb2
import systemconfig_pb2
import devices_pb2
import warrants_pb2

from decimal import Decimal
from colorlog import ColoredFormatter
from administration_client import AdministrationClient

# Initialize the key name

KEY_NAME = 'admin1'

# hard-coded for simplicity (otherwise get the URL from the args in main):
# DEFAULT_URL = 'http://localhost:8008'
# For Docker:
DEFAULT_URL = 'http://rest-api:8008'


def create_console_handler(verbose_level):
    '''Setup console logging.'''
    del verbose_level  # unused
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)
    clog.setLevel(logging.DEBUG)
    return clog


# Logger Setup
def setup_loggers(verbose_level):
    '''Setup logging.'''
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


# Parser Setup
def create_parser(prog_name):
    '''Create the command line argument parser for the administration CLI.'''
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage the administration transaction family',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True



    loadAttestationPropertiesDB_subparser = subparsers.add_parser('loadAttestationPropertiesDB',
                                                                  help='load a new database of attestation results onto the blockchain',
                                                                  parents=[parent_parser])

    loadPolicyDB_subparser = subparsers.add_parser('loadPolicyDB',
                                                   help='load a new policy database onto the blockchain',
                                                   parents=[parent_parser])

    loadSystemConfig_subparser = subparsers.add_parser('loadSystemConfig',
                                                       help='load a new system config file onto the blockchain',
                                                       parents=[parent_parser])

    loadDeviceDB_subparser = subparsers.add_parser('loadDeviceDB',
                                                   help='load a new device database file onto the blockchain',
                                                   parents=[parent_parser])

    loadWarrantDB_subparser = subparsers.add_parser('loadWarrantDB',
                                                    help='load a new warrant database file onto the blockchain',
                                                    parents=[parent_parser])
    loadApplicationDB_subparser = subparsers.add_parser('loadApplicationDB',
                                                        help='load a new database of logging applications onto the blockchain',
                                                        parents=[parent_parser])
    AddDevice_subparser = subparsers.add_parser('AddDevice',
                                                help='Add new device and topic to middlebox dict',
                                                parents=[parent_parser])
    AddDevice_subparser.add_argument('-D',
                                     type=str,
                                     help='Device ID')
    AddDevice_subparser.add_argument('-T',
                                     type=str,
                                     help='Topic for Device')
    return parser


def AddDevice(args):
    '''write new log events in blockchain'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AdministrationClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    response = client.newdevice(str(args.D), str(args.T))
    # print("log Response: {}".format(response))
    print("sent")


# def loadApplicationDB(args):
#     '''Subcommand to load a new device database onto the blockchain.  Calls client class to do submission.'''
#     privkeyfile = _get_private_keyfile(KEY_NAME)
#     client = AdministrationClient(base_url=DEFAULT_URL, key_file=privkeyfile)
#     SerializedApplicationList = buildApplicationList().SerializeToString()
#     response = client.submitApplications(SerializedApplicationList)
#     print("Applications Submission Result: {}".format(response))

def loadAttestationPropertiesDB(args):
    '''Subcommand to load a new properties database onto the blockchain.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AdministrationClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    SerializedPropertiesList = buildPropertiesList().SerializeToString()
    response = client.submitProperties(SerializedPropertiesList)
    print("Properties Submission Result: {}".format(response))


def buildPropertiesList():
    # load csv file and add each Properties entry to a PropertiesList object
    PropertiesList = properties_pb2.PropertiesList()

    with open('../administration_data/AttestationPropertiesDB.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            newPropertiesEntry = makeProperties(row['AttestationType'], row['ReliabilityScore'], row['TimeFunction'],
                                                row['xmin'], row['xmax'])
            print(row['AttestationType'], row['ReliabilityScore'], row['TimeFunction'], row['xmin'], row['xmax'])
            PropertiesList.Properties.extend([newPropertiesEntry])

    return PropertiesList


def makeProperties(attType, relScore, timeFunc, xmin, xmax):
    # Build a Properties object
    newPropertiesEntry = properties_pb2.Properties(
        AttestationType=attType,
        ReliabilityScore=Decimal(relScore),
        TimeFunction=timeFunc,
        xmin=Decimal(xmin),
        xmax=Decimal(xmax)
    )
    return newPropertiesEntry


def loadPolicyDB(args):
    '''Subcommand to load a new policy database onto the blockchain.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AdministrationClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    SerializedPolicyList = buildPolicyList().SerializeToString()
    response = client.submitPolicy(SerializedPolicyList)
    print("Policy Submission Result: {}".format(response))


def buildPolicyList():
    # load csv file and add each Policy to a PolicyList object
    PolicyList = policies_pb2.PolicyList()

    with open('../administration_data/PolicyDB.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            newPolicy = makePolicy(row['DeviceClass'], row['AttestationType'], row['Version'], row['Warrant'],
                                   row['Measurement'])
            print(row['DeviceClass'], row['AttestationType'], row['Version'], row['Warrant'], row['Measurement'])
            PolicyList.Policies.extend([newPolicy])

    return PolicyList


def makePolicy(devClass, attType, version, warrant, measurement):
    # Build a Policy object
    newPolicy = policies_pb2.Policy(
        DeviceClass=devClass,
        AttestationType=attType,
        Version=version,
        Warrant=warrant,
        Measurement=measurement
    )

    return newPolicy


def loadDeviceDB(args):
    '''Subcommand to load a new device database onto the blockchain.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AdministrationClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    SerializedDeviceList = buildDeviceList().SerializeToString()
    response = client.submitDevices(SerializedDeviceList)
    print("Devices Submission Result: {}".format(response))


def buildDeviceList():
    # load csv file and add each Device to a DeviceList object
    DeviceList = devices_pb2.DeviceList()

    with open('../administration_data/DeviceDB.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            newDevice = makeDevice(row['DeviceIdentity'], row['DeviceClass'], row['Version'])
            print(row['DeviceIdentity'], row['DeviceClass'], row['Version'])
            DeviceList.Devices.extend([newDevice])

    return DeviceList


# def buildApplicationList():
#     # load csv file and add each Device to a DeviceList object
#     ApplicationList = application_pb2.ApplicationsList()
#
#     with open('../administration_data/ApplicationDB.csv') as csvfile:
#         reader = csv.DictReader(csvfile)
#         for row in reader:
#             newApplication = makeApplication(row['ApplicationId'], row['Key'])
#             print(row['ApplicationId'], row['Key'])
#             ApplicationList.Applications.extend([newApplication])
#
#     return ApplicationList


# def makeApplication(identity, Key):
#     # Build an Application object
#     newApplication = application_pb2.application(
#         ApplicationId = identity,
#         Key = Key,
#     )
#
#     return newApplication

def makeDevice(identity, devClass, version):
    # Build a Device object
    newDevice = devices_pb2.Device(
        DeviceIdentity=identity,
        DeviceClass=devClass,
        Version=version
    )

    return newDevice


def loadWarrantDB(args):
    '''Subcommand to load a new policy database onto the blockchain.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AdministrationClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    SerializedWarrantList = buildWarrantList().SerializeToString()
    response = client.submitWarrants(SerializedWarrantList)
    print("Warrants Submission Result: {}".format(response))


def buildWarrantList():
    # load csv file and add each Warrant to a WarrantList object
    WarrantList = warrants_pb2.WarrantList()

    with open('../administration_data/WarrantDB.csv') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            newWarrant = makeWarrant(row['Warrantor'], row['Warrantee'], row['AttestationType'])
            print(row['Warrantor'], row['Warrantee'], row['AttestationType'])
            WarrantList.Warrants.extend([newWarrant])

    return WarrantList


def makeWarrant(warrantor, warrantee, attType):
    # Build a Warrant object
    newWarrant = warrants_pb2.Warrant(
        Warrantor=warrantor,
        Warrantee=warrantee,
        AttestationType=attType
    )

    return newWarrant


def loadSystemConfig(args):
    '''Subcommand to load a new system config onto the blockchain.  Calls client class to handle the submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AdministrationClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    SerializedSystemConfig = buildSystemConfig().SerializeToString()
    response = client.submitSystemConfig(SerializedSystemConfig)
    print("Load System Config Result: {}".format(response))


def buildSystemConfig():
    config = configparser.ConfigParser()
    config.read('../administration_data/config.ini')
    security_parameter = config['DEFAULT']['SECURITY_PARAMETER']
    maximum_transaction_interval = config['DEFAULT']['MAXIMUM_TRANSACTION_INTERVAL']
    maximum_transaction_rate = config['DEFAULT']['MAXIMUM_TRANSACTION_RATE']
    punishment_threshold = config['DEFAULT']['PUNISHMENT_THRESHOLD']
    # Build a Systemconfig object
    Systemconfig = systemconfig_pb2.Systemconfig(
        SecurityParameter=int(security_parameter),
        MaximumTransactionInterval=int(maximum_transaction_interval),
        MaximumTransactionRate=int(maximum_transaction_rate),
        PunishmentThreshold=int(punishment_threshold)
    )
    return Systemconfig


# Fetch the private keyfile
def _get_private_keyfile(key_name):
    '''Get the private key for key_name.'''
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, key_name)


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    '''Entry point function for the client CLI.'''
    try:
        if args is None:
            args = sys.argv[1:]
        parser = create_parser(prog_name)
        args = parser.parse_args(args)
        verbose_level = 0
        setup_loggers(verbose_level=verbose_level)

        # Get the commands from cli args and call corresponding handlers
        if args.command == 'loadAttestationPropertiesDB':
            loadAttestationPropertiesDB(args)
        elif args.command == 'loadPolicyDB':
            loadPolicyDB(args)
        elif args.command == 'loadSystemConfig':
            loadSystemConfig(args)
        elif args.command == 'loadDeviceDB':
            loadDeviceDB(args)
        elif args.command == 'loadWarrantDB':
            loadWarrantDB(args)
        elif args.command == 'AddDevice':
            AddDevice(args)
        else:
            raise Exception("Invalid command: {}".format(args.command))

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
