from netmiko import ConnectHandler

connection = ConnectHandler(host='192.168.20.5', port=22,
                            username='6c', password='6c',
                            device_type='cisco_ios')


output = connection.send_command('show running-config', use_textfsm=True)

print(output)
#print(connection.find_prompt())

connection.disconnect()