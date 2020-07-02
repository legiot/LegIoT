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
AttestationManager class interfaces with Sawtooth through the REST API.
It accepts input from a client CLI/GUI/BUI or other interface.
'''

import hashlib
import base64
import random
import time
import requests
import yaml
import cbor
import logging


from threading import Thread

from sawtooth_sdk.protobuf import events_pb2
from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

LOGGER = logging.getLogger(__name__)

# The Transaction Family Name
FAMILY_NAME = 'attestation'
# TF Prefix is first 6 characters of SHA-512("attestation"), FADC96

# Hashing helper method
def _hash(data):
    return hashlib.sha512(data).hexdigest()

# Helper method for address assembly with current transaction family name
def _assembleAddress(public_key):
    return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
             _hash(public_key.encode('utf-8'))[0:64]

class AttestationManagerClient(object):
    '''
    Client Attestation Manager class handles the the submission of transactions
    Supports "submitEvidence" and "trustQuery" functions.
    '''

    def __init__(self, base_url, key_file=None):
        '''Initialize the client class 
           Mainly getting the key pair and computing the address.
        '''
        self._base_url = base_url

        if key_file is None:
            self._signer = None
            return

        try:
            with open(key_file) as key_fd:
                private_key_str = key_fd.read().strip()
        except OSError as err:
            raise Exception(
                'Failed to read private key {}: {}'.format(
                    key_file, str(err)))

        try:
            private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as err:
            raise Exception( \
                'Failed to load private key: {}'.format(str(err)))

        self._signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_key)
        self._public_key = self._signer.get_public_key().as_hex()


        self._address = _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
            _hash(self._public_key.encode('utf-8'))[0:64]

    def getPublicKey(self):
        return self._public_key

    # For each CLI command, add a method to:
    # 1. Do any additional handling, if required
    # 2. Create a transaction and a batch
    # 2. Send to REST API
    
    def submitEvidence(self, evidence, storageKey):
        '''Submit Attestation Evidence to validator.'''
        # Access to administrative databases must be defined
        administrationAddresses = ['5a752685e4842d73555848afa198ee40c32e19a400d2fd1a59fdad8c7b57d25b78757c','5a7526b8d9d9581e82c7c8ec2cb2614bd8da7334cc1335838dd7ad275b9093dbb0a122','5a7526f43437fca1d5f3d0381073ed3eec9ae42bf86988559e98009795a969919cbeca','5a75264f03016f8dfef256580a4c6fdeeb5aa0ca8b4068e816a677e908c95b3bdd2150','5a752639c6f558e7151b5f83e4c1763d427cd0fef5192d2c86ea3db7c5bc1f1546f9ba']
        storageAddress = _assembleAddress(storageKey)
        LOGGER.info('Storage Address %s.',
                storageAddress)
        # Allow access to block-info data and the administration transaction family namespace
        input_address_list = ['00b10c00', '00b10c01', storageAddress]
        input_address_list.extend(administrationAddresses)
        output_address_list = ['00b10c00', '00b10c01', storageAddress]
        return self._wrap_and_send("submitEvidence", evidence, input_address_list, output_address_list, wait=10)

    def submitTrustQuery(self, payload):
        '''Submit a Trust Query to validator.'''
        # Access to administrative databases must be defined
        administrationAddresses = ['5a752685e4842d73555848afa198ee40c32e19a400d2fd1a59fdad8c7b57d25b78757c','5a7526b8d9d9581e82c7c8ec2cb2614bd8da7334cc1335838dd7ad275b9093dbb0a122','5a7526f43437fca1d5f3d0381073ed3eec9ae42bf86988559e98009795a969919cbeca','5a75264f03016f8dfef256580a4c6fdeeb5aa0ca8b4068e816a677e908c95b3bdd2150','5a752639c6f558e7151b5f83e4c1763d427cd0fef5192d2c86ea3db7c5bc1f1546f9ba']
        # Allow access to block-info data and the administration transaction family namespace
        input_address_list = ['00b10c00', '00b10c01', 'fadc96']
        input_address_list.extend(administrationAddresses)
        output_address_list = ['00b10c00', '00b10c01', 'fadc96']
        '''
        # Functionality for automatic trust query handling of client simulation.
        # Multithreading so that clients are able to submit transactions and listen for events at the same time
        filters = [events_pb2.EventFilter(key="verifier",
                                      match_string=
                                      self._public_key,
                                      filter_type=events_pb2.
                                      EventFilter.REGEX_ANY)]
        #events_client.subscribe_to_events(delta_filters=None)
        from events_client import listen_to_events
        t = Thread(target=listen_to_events, args=(filters,))
        t.start()
        LOGGER.info('Listening to events on key %s', self._public_key)    
        LOGGER.info('Sending TrustQuery...')
        #result = start_new_thread(self._wrap_and_send("trustQuery", payload, input_address_list, output_address_list, wait=10))
        '''
        result = self._wrap_and_send("trustQuery", payload, input_address_list, output_address_list, wait=10)  
                                
        return result

    def _send_to_rest_api(self, suffix, data=None, content_type=None):
        '''Send a REST command to the Validator via the REST API.

           Called by _wrap_and_send().
        '''
        url = "{}/{}".format(self._base_url, suffix)
        print("URL to send to REST API is {}".format(url))

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if not result.ok:
                raise Exception("Error {}: {}".format(
                    result.status_code, result.reason))
        except requests.ConnectionError as err:
            raise Exception(
                'Failed to connect to {}: {}'.format(url, str(err)))
        except BaseException as err:
            raise Exception(err)

        return result.text

    def _wait_for_status(self, batch_id, wait, result):
        '''Wait until transaction status is not PENDING (COMMITTED or error).

           'wait' is time to wait for status, in seconds.
        '''
        if wait and wait > 0:
            waited = 0
            start_time = time.time()
            while waited < wait:
                result = self._send_to_rest_api("batch_statuses?id={}&wait={}"
                                               .format(batch_id, wait))
                status = yaml.safe_load(result)['data'][0]['status']
                waited = time.time() - start_time

                if status != 'PENDING':
                    return result
            return "Transaction timed out after waiting {} seconds." \
               .format(wait)
        else:
            return result


    def _wrap_and_send(self, action, data, input_address_list, output_address_list, wait=None):
        '''Create a transaction, then wrap it in a batch.

           Even single transactions must be wrapped into a batch.
           Called by submitEvidence and submitTrustQuery.
        '''
        # Assemble an action and the actual payload in a dictionary
        LOGGER.info('Payload Debug %s.',
                data)
        transactionDictionary = {
            'Action': action,
            'Payload': data
        }

        payload = cbor.dumps(transactionDictionary)

        # Create a TransactionHeader.
        header = TransactionHeader(
            signer_public_key=self._public_key,
            family_name=FAMILY_NAME,
            family_version="1.0",
            inputs=input_address_list,
            outputs=output_address_list,
            dependencies=[],
            payload_sha512=_hash(payload),
            batcher_public_key=self._public_key,
            nonce=random.random().hex().encode()
        ).SerializeToString()

        # Create a Transaction from the header and payload above.
        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=self._signer.sign(header)
        )

        transaction_list = [transaction]

        # Create a BatchHeader from transaction_list above.
        header = BatchHeader(
            signer_public_key=self._public_key,
            transaction_ids=[txn.header_signature for txn in transaction_list]
        ).SerializeToString()

        # Create Batch using the BatchHeader and transaction_list above.
        batch = Batch(
            header=header,
            transactions=transaction_list,
            header_signature=self._signer.sign(header))

        # Create a Batch List from Batch above
        batch_list = BatchList(batches=[batch])
        batch_id = batch_list.batches[0].header_signature

        # Send batch_list to the REST API
        result = self._send_to_rest_api("batches",
                                       batch_list.SerializeToString(),
                                       'application/octet-stream')

        # Wait until transaction status is COMMITTED, error, or timed out
        return self._wait_for_status(batch_id, wait, result)


