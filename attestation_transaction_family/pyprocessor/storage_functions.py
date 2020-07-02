# Copyright 2017 Intel Corporation
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
# -----------------------------------------------------------------------------

import logging
import block_info_pb2
import block_info_functions
import evidence_pb2
import properties_pb2
import policies_pb2
import devices_pb2
import warrants_pb2
import systemconfig_pb2
import address_calculator

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError

# Initialize logger
LOGGER = logging.getLogger(__name__)

# Addresses for global settings to check evidence validity
policy_address = '5a752685e4842d73555848afa198ee40c32e19a400d2fd1a59fdad8c7b57d25b78757c'
properties_address = '5a7526b8d9d9581e82c7c8ec2cb2614bd8da7334cc1335838dd7ad275b9093dbb0a122'
system_config_address = '5a7526f43437fca1d5f3d0381073ed3eec9ae42bf86988559e98009795a969919cbeca'
devices_address = '5a75264f03016f8dfef256580a4c6fdeeb5aa0ca8b4068e816a677e908c95b3bdd2150'
warrants_address = '5a752639c6f558e7151b5f83e4c1763d427cd0fef5192d2c86ea3db7c5bc1f1546f9ba'

# Function to load the global policy list
def fetchPolicyList(context):
    state_entries = context.get_state([policy_address])
    policyList = policies_pb2.PolicyList()
    try:
        StoredPolicyList = state_entries[0].data
        policyList.ParseFromString(StoredPolicyList)
    except:
        raise InternalError('Failed to load policy list')
    return policyList

# Function to load the global properties list
def fetchPropertiesList(context):
    state_entries = context.get_state([properties_address])
    propertiesList = properties_pb2.PropertiesList()
    try:
        StoredPropertiesList = state_entries[0].data
        propertiesList.ParseFromString(StoredPropertiesList)
    except:
        raise InternalError('Failed to load properties list')
    return propertiesList

# Function to load the global system config
def fetchSystemConfig(context):
    state_entries = context.get_state([system_config_address])
    SystemConfig = systemconfig_pb2.Systemconfig()
    try:
        StoredSystemConfig = state_entries[0].data
        SystemConfig.ParseFromString(StoredSystemConfig)
    except:
        raise InternalError('Failed to load system config')
    return SystemConfig

# Function to load the global device list
def fetchDeviceList(context):
    state_entries = context.get_state([devices_address])
    deviceList = devices_pb2.DeviceList()
    try:
        StoredDeviceList = state_entries[0].data
        deviceList.ParseFromString(StoredDeviceList)
    except:
        raise InternalError('Failed to load device list')
    return deviceList

# Function to load the global warrant list
def fetchWarrantList(context):
    state_entries = context.get_state([warrants_address])
    warrantList = warrants_pb2.WarrantList()
    try:
        StoredWarrantList = state_entries[0].data
        warrantList.ParseFromString(StoredWarrantList)
    except:
        raise InternalError('Failed to load warrant list')
    return warrantList

# Loads the right entry for evidence properties
def findEvidenceProperties(context, evidence):
    propertiesList = fetchPropertiesList(context)
    if propertiesList == []:
        LOGGER.info('Properties List is empty')
    else:
        for properties in propertiesList.Properties:
            if (evidence.AttestationType == properties.AttestationType):
                return properties
    return 

# Load the global Security Parameter
def loadSecurityParameter(context):
    SystemConfig = fetchSystemConfig(context)
    if SystemConfig == []:
        LOGGER.info('System Config is empty')
    else:
        SecurityParameter = SystemConfig.SecurityParameter
    return SecurityParameter

# Delete an evidence from the global state
def _deleteEvidence(context, evidence):
    address = address_calculator._assembleEvidenceStorageAddress(evidence)
    state_entries = context.get_state([address])
    evidenceList = evidence_pb2.EvidenceList()

    newEvidenceList = evidence_pb2.EvidenceList()

    if state_entries != []: 
        try:
            StoredEvidenceList = state_entries[0].data
            evidenceList.ParseFromString(StoredEvidenceList)
        except:
            raise InternalError('Failed to load state data - deleteEvidence')
        
        for currentEvidence in evidenceList.Evidences:
                if (currentEvidence != evidence):
                    newEvidenceList.Evidences.extend([currentEvidence])
        
    state_data = newEvidenceList.SerializeToString()
    addresses = context.set_state({address: state_data})

    # check if data was actually written to addresses
    if len(addresses) < 1:
        raise InternalError("State Error")
    # Add event submission
    context.add_event(
            event_type="attestation/evidence_deletion",
            attributes=[("verifier", str(evidence.VerifierIdentity)), ("prover", str(evidence.ProverIdentity))])

# Function to load an evidence list for a storage address
def getEvidenceListFromAddress(context, address):
    state_entries = context.get_state([address])
    if state_entries == []:
        evidenceList = []
    else:   
        try:
            StoredEvidenceList = state_entries[0].data
            evidenceList = evidence_pb2.EvidenceList()
            evidenceList.ParseFromString(StoredEvidenceList)
        except:
            raise InternalError('Failed to load state data - getEvidenceFromAddress')
    return evidenceList
