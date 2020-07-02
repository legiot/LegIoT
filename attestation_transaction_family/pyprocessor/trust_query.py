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
import block_info_pb2
import block_info_functions
import storage_functions
import evidence_pb2
import properties_pb2
import systemconfig_pb2
import trust_query_pb2
import address_calculator
import graph_search
import time
import datetime
import ast
import textwrap

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError

# Initialize logger
LOGGER = logging.getLogger(__name__)

'''
Handling of trust query submission

Input: 
    context - current blockchain state
    payload - submitted trust query from the transaction payload
    sender - sender public key
Output:
    trustpath - event for an existing trustpath
    entrypoint - event for determining the entrypoint
'''
def handleTrustQuery(context, payload, sender):
    LOGGER.info('Trust query received from %s.',
                sender)

    # Read received query back to TrustQuery object
    trustQuery = trust_query_pb2.TrustQuery()
    trustQuery.ParseFromString(payload)

    # Validate trust query correctness according to Section 6.4.3
    _validate_trust_query(context, trustQuery, sender)

    # Call graph search algorithm
    # with Trustee, Trustor, current Security Parameter and Minimal Reliability
    pathFound, finalRating, entryPoint, path = graph_search.buildPath(context, trustQuery.Trustee, trustQuery.Trustor, storage_functions.loadSecurityParameter(context), trustQuery.MinReliability)

    # Process graph search results and emit events
    if pathFound:
        context.add_event(
            event_type="attestation/trustpath",
            attributes=[("verifier", str(trustQuery.Trustor)),("prover", str(trustQuery.Trustee)),("path", str(path)), ("finalRating", str(finalRating))])
    else:
        context.add_event(
            event_type="attestation/entrypoint",
            attributes=[("verifier", str(sender)),("path", str(path)), ("finalRating", str(finalRating)), ("entryPoint", str(entryPoint))])

'''
calculateEdgeTrustScore function to calculate the reliability for a given evidence

Input: 
    context - current blockchain state
    evidence - the evidence to calculate the trust score for
Output:
    finalTrustScore - final score for the given evidence / edge
'''
def calculateEdgeTrustScore(context, evidence):
    # Load the attestation properties for the evidence
    evidenceProperties = storage_functions.findEvidenceProperties(context, evidence)
    if evidenceProperties == []:
        LOGGER.info('Properties List is empty')
    try:
        reliabilityScore = evidenceProperties.ReliabilityScore
        timeFunction = evidenceProperties.TimeFunction
        xmin = evidenceProperties.xmin
        xmax = evidenceProperties.xmax
    except AttributeError:
        raise InvalidTransaction('Could not find properties attributes for evidence')    
    # Calculate the evidence age
    x = _getTimeDifference(context, evidence)
    assert xmin <= xmax
    # Calculate the resulting trust score
    if (x <= xmin):
        trustScore = 1
    elif (xmin < x <= xmax):
        # Parse and evaluate time function: 
        # eval() does not need to be sanitized, administration transaction family input only by administrators
        trustScore = eval(_dedent_string(timeFunction))
    else:
        trustScore = 0
        # Delete evidence from state due to expiration
        storage_functions._deleteEvidence(context, evidence)
        LOGGER.info('Deleting evidence')
    # In addition to the time influence, add static reliability influence
    finalTrustScore = trustScore * reliabilityScore
    return finalTrustScore

# Helper function to format a timestamp in a readable way
def formatTimestamp(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# Dedents a given string
# Needed for the attestation properties function parser (eval) in calculateEdgeTrustScore
def _dedent_string(string):
    if string and string[0] == '\n':
        string = string[1:]
    return textwrap.dedent(string)

# Calculates the temporal proximity of evidence submission time and current time
def _getTimeDifference(context, evidence):
    currentTimestamp = block_info_functions.readLastBlockTime(context)
    timeDiff = currentTimestamp - evidence.Timestamp
    return timeDiff

# Validation of trust query transaction
def _validate_trust_query(context, trustQuery, sender):
    # 1. IDvrf and IDprv are both legitimate participating peers
    try:
        assert (_validate_vrfID(context, trustQuery.Trustor) == True)
    except:
            raise InvalidTransaction('Trustor Assertion Error')
    try:
        assert (_validate_prvID(context, trustQuery.Trustee) == True)
    except:
        raise InvalidTransaction('Trustee Assertion Error')
    # 2. minReliability in [0,1]
    try:
        assert (_validate_minReliability(trustQuery.MinReliability) == True)
    except:
            raise InvalidTransaction('minReliability Assertion Error')

# Function for minReliability validation
def _validate_minReliability(minReliability):
    if ((minReliability >= 0) and (minReliability <= 1)):
        return True
    else:
        return False

# Function for trustor validation
def _validate_vrfID(context, vrfID):
    deviceList = storage_functions.fetchDeviceList(context)
    if deviceList == []:
        LOGGER.info('Device List is empty')
    else:
        for device in deviceList.Devices:
            if (vrfID == device.DeviceIdentity):
                return True
    return False

# Function for trustee validation
def _validate_prvID(context, prvID):
    deviceList = storage_functions.fetchDeviceList(context)
    if deviceList == []:
        LOGGER.info('Device List is empty')
    else:
        for device in deviceList.Devices:
            if (prvID == device.DeviceIdentity):
                return True
    return False
