# Attestation Management System 'LegIoT' based on Hyperledger Sawtooth v1.1.4

#### Setup:
1. Extract to destination.
2. Run `docker-compose -f attestation_management_composer.yml up`
3. Open a session with a administrator client:
	- `docker exec -it administrator-client bash`
4. Load administrative databases to the global state:
	- `administration.py loadPolicyDB && administration.py loadAttestationPropertiesDB && administration.py loadSystemConfig && administration.py loadDeviceDB && administration.py loadWarrantDB`
5. Open a session with any client (e.g., mes):
	- `docker exec -it mes bash`
6. Submit evidences and trust queries. Example:
	```
    attmgr.py submitEvidence 066B 073B SWATT PLC 1.0 7A09AB47D4 true && 
	attmgr.py submitEvidence 098D 066B DIAT Workstation 1.1 65CD9AD691 false && 
	attmgr.py submitEvidence 0794 098D TPM SCADA 1.0 D55B922B96 false &&
	attmgr.py submitEvidence 08FF 066B DIAT Workstation 1.1 65CD9AD691 false &&
	attmgr.py submitEvidence 0D76 098D TPM SCADA 1.0 D55B922B96 false &&
	attmgr.py submitEvidence 0B4D 0794 SGX Server 1.4 745BE192F4 false && attmgr.py trustQuery 0794 073B 0.5
	```
	
#### Further information:
- folder **administration_transaction_family**: handling of administration transactions
- folder **attestation_transaction_family**: handling of attestation transactions (trust query and evidence submission)
- folder **client_simulation**: Data needed for random device attestation simulation between clients. Data used with 'simulation init'
- folder **keys**: Stored administration keys
- folder **protos**: All generated Google Protobuf files
- folder **subscriber**: Subscriber client instance that is able to retrieve all events generated in the network
--> Currently, in evidence submissions arbitrary keys can be used for prover and verifier.
A binding of keys to device identities is needed for a real-world deployment without docker.


	
