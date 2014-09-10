#scn design


#scn protocol
##special characters
*sepm ends commands
*sepc seperates command parameters
*sepu seperates blocks in a command parameter

##keywords
*success signals a success 
*error signals an error
*bytes signals a byte transfer (for debug)

##bytes subprotocol
socket opens byte receive request with a valid size range
bytes keyword is read and checked, sends error and returns if it doesn't exists
size is read and checked, sends error and returns if conversion into int failed or size is bigger or smaller than the size range
send success
sender sends now the binary blob + sepc or sepm
receiver receives till size and checks for sepc or sepm
##examples
*get_service sepc samplename sepc sampleservice sepm
*get_service sepc samplename sepc sampleservice sepm info sepm
*test sepc bytes 5 <waits for a success> willi sepm 



