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
Command line interface for attestation TF.
Parses command line arguments and passes to the attmgr_client class
to process.
'''

import argparse
import logging
import os
import sys
import traceback
import evidence_pb2
import trust_query_pb2
import csv
import time
import random
import itertools

from decimal import Decimal
from colorlog import ColoredFormatter
from attmgr_client import AttestationManagerClient

KEY_NAME = 'client1'

# hard-coded for simplicity (otherwise get the URL from the args in main):
#DEFAULT_URL = 'http://localhost:8008'
# For Docker:
DEFAULT_URL = 'http://rest-api:8008'

# Initialize logger
LOGGER = logging.getLogger(__name__)

# Initialize console
def create_console_handler(verbose_level):
    '''Setup console logging.'''
    del verbose_level # unused
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

# Logger setup
def setup_loggers(verbose_level):
    '''Setup logging.'''
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))

# Assembly of parsers for the transaction commands
def create_parser(prog_name):
    '''Create the command line argument parser for the attestation CLI.'''
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage attestation transaction family via CLI',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True

    submitEvidence_subparser = subparsers.add_parser('submitEvidence',
                                           help='submit an attestation evidence',
                                           parents=[parent_parser])
    submitEvidence_subparser.add_argument('vrfID',
                                #type=string,
                                help='Verifier Public Key')
    submitEvidence_subparser.add_argument('prvID',
                                #type=string,
                                help='Prover Public Key')
    submitEvidence_subparser.add_argument('attType',
                                #type=string,
                                help='Attestation Type')
    submitEvidence_subparser.add_argument('prvDeviceClass',
                                #type=string,
                                help='Prover Device Class')
    submitEvidence_subparser.add_argument('prvVersion',
                                #type=string,
                                help='Prover Version')
    submitEvidence_subparser.add_argument('measurement',
                                #type=string,
                                help='Measurement Value')
    submitEvidence_subparser.add_argument('isWarrant',
                                #type=string,
                                help='Was this measurement part of a warant relationship?')
                                
    trustQuery_subparser = subparsers.add_parser('trustQuery',
                                           help='Query a trust link',
                                           parents=[parent_parser])
    trustQuery_subparser.add_argument('trustor',
                                #type=string,
                                help='The device to establish trust')	
    trustQuery_subparser.add_argument('trustee',
                                #type=string,
                                help='The device to be attested')	
    trustQuery_subparser.add_argument('minReliability',
                                #type=string,
                                help='Minimum required reliability')	
    simulation_subparser = subparsers.add_parser('simulation',
                                           help='attestation simulation',
                                           parents=[parent_parser])	
    simulation_subparser.add_argument('mode',
                                #type=string,
                                help='init - run')	 		  	  
    return parser

# Command to handle an evidence submission from the command line
def submit_evidence(args):
    '''Subcommand to submit an attestation evicende.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationManagerClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    encodedEvidence = buildEvidencePayload(args.vrfID, args.prvID, args.attType, args.prvDeviceClass, args.prvVersion, args.measurement, args.isWarrant)
    response = client.submitEvidence(encodedEvidence, args.prvID)
    print("Evidence Submission Result: {}".format(response))

# Command to handle an evidence submission as a result to an entrypoint event
def submit_evidence_direct(vrfID,prvID,attType, prvDeviceClass, prvVersion, measurement,isWarrant):
    '''Subcommand to submit an attestation evicende.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationManagerClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    #evidenceBytes = buildEvidencePayload(args.attType, args.measurement, args.vrfID, args.vrfArch, args.prvID, args.prvArch, args.attScope, args.isWarrant)
    encodedEvidence = buildEvidencePayload(vrfID,prvID,attType, prvDeviceClass, prvVersion, measurement,isWarrant)
    response = client.submitEvidence(encodedEvidence, prvID)
    print("Evidence Submission Result: {}".format(response))

# Command to handle a trust query from the command line
def trustQuery(args):
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationManagerClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    queryBytes = buildTrustQueryPayload(args.trustor, args.trustee, args.minReliability)
    response = client.submitTrustQuery(queryBytes)
    print("Trust Query Result: {}".format(response))

# Command to handle a trust query from the simulation environment
def trustQueryDirect(trustor, trustee, minReliability):
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationManagerClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    queryBytes = buildTrustQueryPayload(trustor, trustee, minReliability)
    response = client.submitTrustQuery(queryBytes)
    print("Trust Query Result: {}".format(response))

# Builder method for the evidence object (protobuf)
def buildEvidencePayload(vrfID,prvID,attType, prvDeviceClass, prvVersion, measurement,isWarrant):
    encodedEvidence = evidence_pb2.Evidence(
        VerifierIdentity = vrfID,
        ProverIdentity = prvID,
        AttestationType = attType,
        ProverDeviceClass = prvDeviceClass,
        ProverVersion = prvVersion,
        Measurement = measurement,
        isWarrantAttestation = isWarrant
        # Timestamp should not be set here because it can only be trusted on the smart contract side
        # If set here it is overwritten from the Transaction Processor
    ).SerializeToString()
    return encodedEvidence

# Builder method for the trust query object (protobuf)
def buildTrustQueryPayload(trustor, trustee, minReliability):
    trustQuery = trust_query_pb2.TrustQuery(
        Trustor = trustor,
        Trustee = trustee,
        MinReliability = Decimal(minReliability)
    ).SerializeToString()
    return trustQuery

# Simulation functionality to simulate trust queries and evidence submissions
def simulation(args):
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationManagerClient(base_url=DEFAULT_URL, key_file=privkeyfile)
    vrfID = client.getPublicKey()
    if (args.mode == 'init'):
        simulation_init(vrfID)
    elif (args.mode == 'del'):
        simulation_delete()
    else: 
        simulation_go(vrfID)
    
# Initialize simulation
def simulation_init(vrfID):
    # Change to desired device type:
    # row = [vrfID, 'SCADA']
    with open('../../client_simulation/Devices.csv', 'a') as csvFile:
        writer = csv.writer(csvFile)
        writer.writerow(row)
    csvFile.close()

# Delete simulation data
def simulation_delete():
    with open('../../client_simulation/Devices.csv', 'w+') as csvFile:
        row = ['PublicKey', 'DeviceClass']
        writer = csv.writer(csvFile)
        writer.writerow(row)
    csvFile.close()
    with open('../../client_simulation/Graph.csv', 'w+') as csvFile:
        row = ['Verifier', 'Prover']
        writer = csv.writer(csvFile)
        writer.writerow(row)
    csvFile.close()

# Run the simulation
def simulation_go(vrfID):
    while(1):
        #prvID,attType, prvDeviceClass, prvVersion, measurement = loadRandomProverData(vrfID)
        #submit_evidence_direct(vrfID,prvID,attType, prvDeviceClass, prvVersion, measurement,'false')
        #time.sleep( 10 )
        prvID,attType, prvDeviceClass, prvVersion, measurement = loadRandomProverData(vrfID)
        print("Trustquery from: " + vrfID + "to " + prvID)
        trustQueryDirect(vrfID, prvID, '0.6')
        time.sleep( 10 )

# Load data for a given prover
def loadProverData(prvID):
    prvDeviceClass = None
    attType = None
    prvVersion = None
    measurement = None
    with open('../../client_simulation/Devices.csv', 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if (row['PublicKey'] == prvID):
                prvDeviceClass = row['DeviceClass']

    with open('../../administration_transaction_family/administration_data/PolicyDB.csv') as csvfile2:
        reader = csv.DictReader(csvfile2)
        for row in reader:
            if (row['DeviceClass'] == prvDeviceClass):
                attType = row['AttestationType']
                prvVersion = row['Version']
                measurement = row['Measurement']
    return attType, prvDeviceClass, prvVersion, measurement

# Load data for a random prover
def loadRandomProverData(vrfID):
    attType = None
    prvVersion = None
    measurement = None

    prvID, prvDeviceClass = _getRandomDevice(vrfID)

    with open('../../administration_transaction_family/administration_data/PolicyDB.csv') as csvfile2:
        reader = csv.DictReader(csvfile2)
        for row in reader:
            if (row['DeviceClass'] == prvDeviceClass):
                attType = row['AttestationType']
                prvVersion = row['Version']
                measurement = row['Measurement']
    
    print('Random prover data:' + vrfID + ' , ' + prvID + ' , ' + attType + ' , ' + prvDeviceClass + ' , ' + prvVersion + ' , ' + measurement)

    return prvID,attType, prvDeviceClass, prvVersion, measurement

# Choose random device from the device list
def _getRandomDevice(vrfID):
    with open('../../client_simulation/Devices.csv', 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        chosen_row = random.choice(list(reader))
        print(chosen_row)
        if ((chosen_row[0] == 'PublicKey') or (chosen_row[0] == vrfID)):
            # do it again until not first row was chosen
            prvID , prvDeviceClass = _getRandomDevice(vrfID)
        else:
            prvID = chosen_row[0]
            prvDeviceClass = chosen_row[1]
    return prvID, prvDeviceClass

# Load the private keyfile
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
        if args.command == 'submitEvidence':
            submit_evidence(args)
        elif args.command == 'trustQuery':
            trustQuery(args)
        elif args.command == 'simulation':
            simulation(args)
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
