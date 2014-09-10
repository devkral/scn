#scn design
scn consists of servers and clients
server contain hashsums of clientcertificates, hashed authentificationsecrets and ip or other contact address.
clients contains a list with ports and names
clients contains a db with known server certs, friend nodes and a name and service list the client should serve

client looks other client on server up. it requests the cert of the contacted client and compares it with hash
the hash is generated from the registered name on the server and the public cert (for privacy reasons, because only certificate hashes could be used to track clients (salting))



#scn protocol
##special characters
* sepm ends commands
* sepc seperates command parameters
* sepu seperates blocks in a command parameter

##keywords
* success signals a success 
* error signals an error
* bytes signals a byte transfer (for debug)

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



