#! /usr/bin/env python3
import os

#max_client_receive_it=5
max_user_services=10
max_service_nodes=10
min_name_length=6
max_name_length=30
max_normal_size=20000
protcount_max=30
buffersize=512
secret_size=512 #only relevant for client because server uses hash
key_size=4096
default_config_folder=os.getenv("HOME")+os.sep+".scn"+os.sep

debug_mode=True
show_error_mode=True

#client
client_show_incomming_commands=True
scn_client_port=4041

#server
server_host="localhost"
scn_server_port=4040
