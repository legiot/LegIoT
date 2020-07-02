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

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
import logging
import address_calculator
import storage_functions
import trust_query

# Initialize logger
LOGGER = logging.getLogger(__name__)

'''
buildPath function for establishing a path between verifier and prover

Input: 
    context - current blockchain state
    proverID - prover key or identity
    verifierID - verifier key or identity
    SecurityParameter - maximum allowed hop distance (search depth)
    minReliability - minimum required reliability for resulting path
Output:
    pathFound - boolean if a final path was found
    finalRating - rating of the path
    entryPoint - node the verifier needs to attest to enter the graph
    path - sequence of nodes that build the final path
'''
def buildPath(context, proverID, verifierID, SecurityParameter, minReliability):

    # Initialization of return values
    pathFound = False
    finalRating = 0
    entryPoint = None
    path = None

    # Initialization of search parameters
    maxDepth = SecurityParameter
    currentDepth = 0
    Fringe = []
    newFringe = []
    '''
    visited[node][0] - path reliability from node to prv
    visited[node][1] - node depth
    visited[node][2] - path from node to prv
    '''
    visited = {}

    # Prover equals verifier, return
    if proverID == verifierID:
                    pathFound = True
                    finalRating = 1
                    LOGGER.info('Verifier equals Prover')
                    return pathFound, finalRating, entryPoint, path

    # Initialization for prover node
    visited[proverID] = [1, currentDepth, proverID]
    Fringe.append(proverID)
    # Prover initialized, increase currentDepth    
    currentDepth +=1

    # Iterative expansion until maxDepth
    while (currentDepth <= maxDepth):
        LOGGER.info('Expanding nodes for depth %s', currentDepth)
        # Expand each node in the fringe
        for node in Fringe:
            EvidenceList = storage_functions.getEvidenceListFromAddress(context, address_calculator._assembleAddress(node))
            if EvidenceList == []:
                LOGGER.info('Evidence List is empty')
                continue
            # For each evidence, add parent to visited with the resulting path and path score
            for evidence in EvidenceList.Evidences:
                newScore = trust_query.calculateEdgeTrustScore(context, evidence)
                # If evidences with a score of 0 are still contained, they are deleted now. Thus they must not be added to visited[]!
                if newScore == 0:
                    LOGGER.info('Continuing...')
                    continue
                if currentDepth == 1:
                    parentScore = newScore
                else: 
                    # Calculate new trust score
                    parentScore = newScore * visited[node][0]
                if ((evidence.VerifierIdentity == verifierID) and (parentScore >= minReliability)):
                    # A path to the verifier was found! Return.
                    pathFound = True
                    finalRating = parentScore
                    path = visited[evidence.ProverIdentity][2]
                    LOGGER.info('Verifier path was found. TrustScore: %s with Path: %s', finalRating, (path + ',' + evidence.VerifierIdentity))
                    return pathFound, finalRating, entryPoint, path

                # A check is required to exclude cyclic paths back to a prover     
                if (((evidence.VerifierIdentity in visited) == False) and (currentDepth < maxDepth)):
                    visited[evidence.VerifierIdentity] = [parentScore, currentDepth, ((visited[evidence.ProverIdentity][2]) + ',' + evidence.VerifierIdentity)]
                    newFringe.append(evidence.VerifierIdentity)
        # Assign the new fringe and increase current depth
        Fringe.clear()
        Fringe.extend(newFringe)
        newFringe.clear()
        currentDepth +=1

    # This part is only reached when no path between verifer and prover was found
    # Calculate the optimal entryPoint here for the list of visited nodes:
    entryPoint, finalRating, path = calculateEntryPoint(visited, minReliability)

    return pathFound, finalRating, entryPoint, path

'''
calculateEntryPoint function to determine the best possible graph entry point

Input: 
    visited - list of visited candidate nodes
    minReliability - minimum required reliability for resulting path
Output:
    entryPoint - node the verifier needs to attest to enter the graph
'''
def calculateEntryPoint(visited, minReliability):
    candidates = []
    # Add all nodes that fulfil the minimal reliability requirement to the candidates list
    for key, value in visited.items():
        # Delete all candidates that do not fulfil the minimal reliability requirement
        if value[0] > minReliability:
            newCandidate = [key, value[0], value[1], value[2]]
            candidates.append(newCandidate)
    # Sort candidates in the following order: 
    # 1. Furthest distance to prover 
    candidates.sort(key=_getReliability, reverse = True)
    # 2. Highest reliability for equal distances
    candidates.sort(key=_getDepth, reverse= True)
    LOGGER.info('Candidate found: %s out of all candidates: %s', candidates[0], candidates)

    return _getNodeID(candidates[0]), _getReliability(candidates[0]), _getPath(candidates[0])

# Getter functions for list elements
def _getNodeID(elem):
    return elem[0]

def _getReliability(elem):
    return elem[1]

def _getDepth(elem):
    return elem[2]

def _getPath(elem):
    return elem[3]