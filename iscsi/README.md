# An example of iSCSI Session
First request from initiator (client) is [Login Request](https://datatracker.ietf.org/doc/html/rfc3720#section-10.12), which contains parameters of connection in ASCII format. Server should response with [Login Response](https://datatracker.ietf.org/doc/html/rfc3720#section-10.13). Depending on parameter ```SessionType``` in initiator's request it could be [two types of session](https://datatracker.ietf.org/doc/html/rfc3720#section-3.3 ).
## Discovery session
If ```SessionType=Discovery```, then it is discovery session. Besides Login Request and Login Response, it could contain only [Text Request](https://datatracker.ietf.org/doc/html/rfc3720#section-10.10) from initiator and [Text Response](https://datatracker.ietf.org/doc/html/rfc3720#section-10.11) from server. In Text Request initiator asks for targets, that it want to get information about. Server responds with name, address and id of all targets.

## Normal operational session
If ```SessionType``` not specified, it is a normal session. After login phase, initiator usually uses only  [SCSI command](https://datatracker.ietf.org/doc/html/rfc3720#section-10.3) to get information about logical units, read data and so on. Server responds with [SCSI Data-In](https://datatracker.ietf.org/doc/html/rfc3720#section-10.7). [Basic Header Segment](https://datatracker.ietf.org/doc/html/rfc3720#section-10.2.1) (BHS) contains [Command Descriptor Block](https://datatracker.ietf.org/doc/html/rfc3720#section-10.3.5) (CDB) from 32 (inclusive) to 48 byte (not inclusive). First byte of CDB -- opcode -- specifies a type of operation. Also BHS from 8 (inclusive) to 16 (not inclusive) bytes contains a Logical Unit Number (LUN) -- identificator of server's target which command addresses to.
### Inquiry
If first byte of CDB is ```0x12```, it is an inquiry command. Initiator uses it first. If second byte is 0, it's standart inquiry request, otherwise, it's vital inquiry request. For standart inquiry request server responds with name of company and name of LUN. In vital inquiry request with third byte set to 0, server responds with all vital pages numbers that it has. After that, initiator requests for all vital pages successively. One of the important vital pages is 0x83 -- device identification. Server responds with target's name, id and some other parameters.
### Report LUNs
After getting information about first target, initiator asks for list of all targets by setting first byte of CDB to ```0xA0```. Server responds with list of LUN. After that initiator request inquiry data for all other targets.
### Test Unit Ready
After getting information about all targets, initiator asks if target ready to take requests by using Test Unit Ready command (first byte ix ```0x00```). Server should respond with empty CDB if target is ready and non-empty otherwise.
### Read Capacity
If target is ready, initiator continue to get information about it. If first byte of CDB is ```0x9E```, initiator asks for target's read capacity. Server responds with size of blocks, offset and number of blocks of target.
### Mode sense
Mode sense (CDB opcode is ```0x1A```) is an another request for target's parameters. From now server responds with empty data.
### Report Opcodes
With CDB opcode set to ```0xA3```, initiator asks for command's bitmask. Server should respond a bitmask for every asked command fith bits that it supports.
### Read
After all, with CDB opcode ```0x28``` initiator asks for data from logical unit. Server reponds with this data.
### NOP-In and NOP-Out
Among other things, client may sometimes ping server with [NOP-In](https://datatracker.ietf.org/doc/html/rfc3720#section-10.19) command. Server should reponse with [NOP-Out](https://datatracker.ietf.org/doc/html/rfc3720#section-10.18).
