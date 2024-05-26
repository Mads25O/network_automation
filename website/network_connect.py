from netmiko import ConnectHandler
import napalm

ip_address = '192.168.87.20'

driver = napalm.get_network_driver('ios')
device = driver(
    hostname = ip_address,
    username = '6c',
    password = '6c'
)
device.open()


connection = ConnectHandler(
    host = ip_address,
    port = 22,
    username = 'mads', 
    password = 'mads',
    device_type = 'cisco_ios')

output = connection.send_command('show ip int brief')

print(output)
print(connection.find_prompt())

connection.disconnect()