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
import hashlib
import block_info_functions
import address_calculator
import evidence_pb2
import policies_pb2
import storage_functions

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError

# Initialize logger
LOGGER = logging.getLogger(__name__)

'''
Handling of attestation evidence submission
Input: 
    context - current blockchain state
    encodedEvidence - submitted evidence from the transaction payload
    sender - sender public key
Output:
    evidence_submission - event that notifies about a successful evidence submission
'''
def handleEvidenceSubmission(context, encodedEvidence, sender):
    LOGGER.info('Received Evidence from Verifier %s.',
                sender)

    # Read received evidence back to Evidence object
    evidence = evidence_pb2.Evidence()
    evidence.ParseFromString(encodedEvidence)

    # Evidence verification according to Section 6.4.2
    _validate_evidence(context, evidence, sender)

    # Calculate the address to store the evidence. Default: ProverIdentity
    storageAddress = address_calculator._assembleAddress(evidence.ProverIdentity)

    # Set current timestamp for new evidence
    _setEvidenceTimestamp(context, evidence)

    # Logging of complete evidence
    LOGGER.info('Evidence --- VerifierIdentity: %s , ProverIdentity: %s , AttestationType: %s , ProverDeviceClass: %s , ProverVersion: %s , Measurement: %s , isWarrant: %s , Timestamp: %s',
                evidence.VerifierIdentity, evidence.ProverIdentity, evidence.AttestationType, evidence.ProverDeviceClass, evidence.ProverVersion, evidence.Measurement, evidence.isWarrantAttestation, evidence.Timestamp)


    # Store evidence to the global state
    _storeEvidence(context, evidence, storageAddress)

    # Add event submission
    context.add_event(
            event_type="attestation/evidence_submission",
            attributes=[("verifier", str(evidence.VerifierIdentity)), ("prover", str(evidence.ProverIdentity))])

# Method to set the evidence timestamp to current time
def _setEvidenceTimestamp(context, evidence):
    # Retrieve timestamp for current block
    timestamp = block_info_functions.readLastBlockTime(context)
    # Embed timestamp into evidence
    evidence.Timestamp = timestamp

'''
Method to store an evidence

Input: 
    context - current blockchain state
    evidenceToStore - the evidence to store
    address - storage address
Raises:
    Internal Error - State Data Error
'''
def _storeEvidence(context, evidenceToStore, address):

    # Retrieve all entries at the given address
    state_entries = context.get_state([address])
    evidenceList = evidence_pb2.EvidenceList()

    if state_entries == []:
        LOGGER.info('No previous evidences, creating new list for address %s',
                    address)
        evidenceList.Evidences.extend([evidenceToStore])
    else:   
        LOGGER.info('Appending evidence to existing list for address %s',
                    address)
        try:
            StoredEvidenceList = state_entries[0].data
            evidenceList.ParseFromString(StoredEvidenceList)
            evidenceList.Evidences.extend([evidenceToStore])
        except:
            raise InternalError('Failed to load state data')
        
    state_data = evidenceList.SerializeToString()
    LOGGER.info('State Data String: %s',
                        state_data)
    addresses = context.set_state({address: state_data})

    # Check if data was actually written to addresses
    if len(addresses) < 1:
        raise InternalError("State Error")

# Validation of an evidence according to Section 6.4.2
def _validate_evidence(context, evidence, sender):
    # 1. IDvrf is signer of the transaction (uncomment when actual keys are used)
    # assert (evidence.VerifierIdentity == sender)
    # 2. IDvrf and IDprv are both legitimate participating peers
    try:
        assert (_validate_vrfID(context, evidence.VerifierIdentity) == True)
    except:
            raise InvalidTransaction('Verifier Assertion Error')
    try:
        assert (_validate_prvID(context, evidence.ProverIdentity) == True)
    except:
        raise InvalidTransaction('Prover Assertion Error')
    proverClass = _lookupProverClass(context, evidence.ProverIdentity)
    # 3. Clprv matches the returned prover device class
    try:
        assert (proverClass == evidence.ProverDeviceClass)
    except:
        raise InvalidTransaction('Prover Class Assertion Error')
    # 4. Validate measurement
    isWarrant = _validate_measurement(context, evidence)
    # 5. Validate warrant
    try:
        assert (_validate_isWarrant(context, evidence.VerifierIdentity, evidence.ProverIdentity, evidence.AttestationType, evidence.isWarrantAttestation, isWarrant) == True)
    except:
        raise InvalidTransaction('Warrant Assertion Error')
    
# Returns the device class of a given prover
def _lookupProverClass(context, proverID):  
    deviceList = storage_functions.fetchDeviceList(context)
    if deviceList == []:
        LOGGER.info('Device List is empty')
    else:
        for device in deviceList.Devices:
            if (proverID == device.DeviceIdentity):
                return device.DeviceClass
    return False

# Function to validate a measurement
def _validate_measurement(context, evidence):
    success, isWarrant = isValidPolicyEntry(context, evidence)
    if not success:
            raise InvalidTransaction(
                'Measurement not in Policy Database!')
    return isWarrant

# Function to verify, if a valid policy entry exists for this evidence
def isValidPolicyEntry(context, evidence):
    # Retrieve all policy entries at the given address
    policyList = storage_functions.fetchPolicyList(context)
    if policyList == []:
        LOGGER.info('Policy List is empty')
    else:
        for policy in policyList.Policies:
            if ((evidence.ProverDeviceClass == policy.DeviceClass)
            and (evidence.AttestationType == policy.AttestationType)
            and (evidence.ProverVersion == policy.Version)
            and (evidence.Measurement == policy.Measurement)):
                LOGGER.info('Found a matching measurement :)')
                return True, (policy.Warrant)
    LOGGER.info('No matching measurement found for measurement: %s', evidence.Measurement)

    return False, None

# Function for verifier validation
def _validate_vrfID(context, vrfID):
    deviceList = storage_functions.fetchDeviceList(context)
    if deviceList == []:
        LOGGER.info('Device List is empty')
    else:
        for device in deviceList.Devices:
            if (vrfID == device.DeviceIdentity):
                return True
    return False

# Function for prover validation
def _validate_prvID(context, prvID):
    deviceList = storage_functions.fetchDeviceList(context)
    if deviceList == []:
        LOGGER.info('Device List is empty')
    else:
        for device in deviceList.Devices:
            if (prvID == device.DeviceIdentity):
                return True
    return False

# Method to check whether a warrant relationship is required and valid
def  _validate_isWarrant(context, vrf, prv, attType, isWarrantEvidence, isWarrantPolicy):
    if (isWarrantEvidence != isWarrantPolicy):
        # Evidence and policy properties do not match!
        return False
    if (isWarrantPolicy == 'false'):
        # No warrant required. Return True!
        return True
    warrantList = storage_functions.fetchWarrantList(context)
    if warrantList == []:
        LOGGER.info('Warrant List is empty')
    else:
        for warrant in warrantList.Warrants:
            if ((vrf == warrant.Warrantor)
            and (prv == warrant.Warrantee)
            and (attType == warrant.AttestationType)):
                LOGGER.info('Found a matching warrant!')
                return True
    LOGGER.info('No matching measurement found for warrant: %s -> %s', vrf, prv)
    return False

