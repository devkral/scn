
# Design Outline of Secure Communication Nodes ('scn') Project
+ 'scn' is a Client-Server-architecture.
+ The server contains hashsums of client certificates, hashed 
 authentication secrets and ips (or other contact methods).
+ Clients contains a list with ports and names.
+ clients contains a database with known server certs, friend-nodes, 
 and a name and service list that the client should serve.
+ A client can look up another client on server. It requests next to the ip address the cert 
 of the client to be contacted, and compares it with a hash value.
+ This hash is generated from the name (on the server) of registered clients and its public cert (for privacy reasons, because only using
 certificate hashes could be used to track clients (salting)).


#scn protocol
##special characters
* sepm ends commands
* sepc seperates command parameters
* sepu seperates blocks in a command parameter

##keywords
* success signals a success 
* error signals an error
* bytes signals a byte transfer (for debug)

##reserved names
* admin: as well as service as name

##bytes subprotocol
socket opens byte receive request with a valid size range
bytes keyword is read and checked, sends error and returns if it doesn't exists
size is read and checked, sends error and returns if conversion into int failed or size is bigger or smaller than the size range
send success
sender sends now the binary blob + sepc or sepm
receiver receives till size and checks for sepc or sepm
##examples
* get_service sepc samplename sepc sampleservice sepm
* get_service sepc samplename sepc sampleservice sepm info sepm
* test sepc bytes 5 <waits for a success> willi sepm 


#Design old
##client-client
client gets connectmethod and address by server
client connects with data. If it fails it uses the next one
if connection succeeds:
  send get_cert get cert, verify and upgrade connection

  send hello+sepc+port get connecttype (e.g. wrap, direct)
