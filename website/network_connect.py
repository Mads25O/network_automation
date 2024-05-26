from netmiko import ConnectHandler
import napalm

ip_address = '192.168.87.20'


########### NAPALM ###########
#driver = napalm.get_network_driver('ios')
#device = driver(
#    hostname = ip_address,
#    username = '6c',
#    password = '6c'
#)
#device.open()

########### Netmiko ###########
connection = ConnectHandler(
    host = ip_address,
    port = 22,
    username = '6c', 
    password = '6c',
    device_type = 'cisco_ios')

vlan_id = '20'
vlan_name = 'Orders'

config_commands = [
    f'vlan {vlan_id}',
    f'name {vlan_name}',
    f'interface vlan {vlan_id}',
    f'ip address 192.168.100.120 255.255.255.0'
]

#output = connection.send_config_set(config_commands)
output = connection.send_command('sh ip int br', use_textfsm=True)

#save_output = connection.send_command('write memory')

connection.disconnect()