#! /usr/bin/env python3
import os

#max_client_receive_it=5
max_user_services=10 #how many services can a user have
max_service_nodes=10 #how many nodes can a service have
min_name_length=6
max_name_length=15
max_message_length=30
max_cmd_size=30
protcount_max=10 
buffersize=512
#hex_hashsize=64
secret_size=512 #size of generated secret
key_size=4096
max_cert_size=10000
hash_hex_size=64
default_config_folder=os.getenv("HOME")+os.sep+".scn"+os.sep
scn_cache_timeout=60*1


debug_mode=True
show_error_mode=True

scn_host="localhost"

#client
client_show_incomming_commands=True
scn_client_port=4041

#server

scn_server_port=4040
