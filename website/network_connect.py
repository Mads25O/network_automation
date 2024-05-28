from netmiko import ConnectHandler

ip_address = '192.168.87.20'

connection = ConnectHandler(
    host = ip_address,
    port = 22,
    username = '6c', 
    password = '6c',
    device_type = 'cisco_ios')



output = connection.send_command('sh vlan br', use_textfsm=True)
print(output)


connection.disconnect()