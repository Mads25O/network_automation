from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, session
from flask_login import login_required, current_user
from .models import Note, Networks, Routers
from . import db
import json
from netmiko import ConnectHandler

network = Blueprint('network', __name__, template_folder='templates/network_managing')

@network.route('/create-network', methods=['GET', 'POST'])
@login_required
def create_network():
    if request.method == 'POST':
        network_name = request.form.get('network_name')
        host = request.form.get('host')
        username = request.form.get('username')
        password = request.form.get('password')
        
        

        network = Networks.query.filter_by(user_id=current_user.id).count()
        network_id = int(network) + 1
        
        new_network = Networks(network_id=network_id, network_name=network_name, host=host, 
                               username=username, password=password, 
                               user_id=current_user.id)
        

        db.session.add(new_network)
        db.session.commit()

        

        flash('Network created!', category='success')
        return redirect(url_for('network.manage_networks'))
    return render_template('create_network.html', user=current_user)


'''@network.route('/manage-network', methods=['GET', 'POST'])
@login_required
def manage_networks():
    if request.method == 'POST':
        
        if request.form.get('connect_button'):
            network_id = request.form['connect_button']
            session["network_id"] = network_id
            return redirect(url_for('network.connect'))
        
    return render_template('network_managing/manage_networks.html', user=current_user)'''


@network.route('/edit-network', methods=['GET', 'POST'])
@login_required
def edit_network():
    network_id = session["network_id"]
    network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    network_name = network.network_name
    host = network.host
    username = network.username
    password = network.password

    if request.method == 'POST':
        
        if request.form['submit_button'] == 'delete':
            network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).delete()
            db.session.commit()
            return redirect(url_for('network.manage_networks'))

        else:
            new_network_name = request.form.get('network_name')
            new_host = request.form.get('host')
            new_username = request.form.get('username')
            new_password = request.form.get('password')

            
            network.network_name = new_network_name
            network.host = new_host
            network.username = new_username
            network.password = new_password
            
            db.session.commit()
                

            return redirect(url_for('network.manage_networks'))
        
    return render_template('network_managing/edit_network.html', user=current_user, network_name=network_name, host=host, username=username, password=password)


@network.route('/connect', methods=['GET', 'POST'])
@login_required
def connect():
    network_id = session["network_id"]
    network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    network_name = network.network_name
    host = network.host
    username = network.username
    password = network.password

    interfaces = ['0', '0']
    vlans = ['0', '0']

    try:
        connection = ConnectHandler(host=host, port=22,
                                    username=username, password=password,
                                    device_type='cisco_ios')
        
        interfaces = connection.send_command('sh ip int br', use_textfsm=True)
        vlans = connection.send_command('sh vlan br', use_textfsm=True)
        session["vlans"] = vlans
        session["interfaces"] = interfaces
        

    except:
        flash('Can\'t connect.', category='error')


    if request.form.get('change_button'):

        network_id = request.form['change_button']
        session["network_id"] = network_id
        return redirect(url_for('network.edit_network'))
        
    if request.form.get('connect_button'):
        network_id = request.form['connect_button']
        session["network_id"] = network_id
        return redirect(url_for('network.connect'))


    if request.form.get('access_button'):

        network_id = request.form['access_button']
        session["network_id"] = network_id
        session["extended_access"] = 'False'

        return redirect(url_for('network.access_list'))
        
    if request.form.get('vlan_button'):

        network_id = request.form['vlan_button']
        session["network_id"] = network_id
        return redirect(url_for('network.vlans'))

        
    if request.form.get('dhcp_button'):

        
        network_id = request.form['dhcp_button']
        session["network_id"] = network_id
        return redirect(url_for('network.dhcp'))

    if request.form.get('router_button'):
        network_id = request.form['router_button']
        session["network_id"] = network_id
        return redirect(url_for('network.router'))
    
    if request.form.get('ntp_button'):
        network_id = request.form['ntp_button']
        session["network_id"] = network_id
        return redirect(url_for('network.ntp'))
    
    if request.form.get('port_sec_button'):
        network_id = request.form['port_sec_button']
        session["network_id"] = network_id
        return redirect(url_for('network.port_security'))
        
    
    return render_template('network_managing/connect.html', 
                           user=current_user, 
                           network_name=network_name, 
                           host=host, username=username, 
                           password=password, 
                           interfaces=interfaces,
                           vlans=vlans)

@network.route('/access-list', methods = ['GET', 'POST'])
@login_required
def access_list():

    # Netværk
    network_id = session["network_id"]
    network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    network_name = network.network_name
    host = network.host
    username = network.username
    password = network.password

    # Tomme variabler
    access_list_name = None
    hostname = None
    permit_or_deny = None
    any_or_host = None
    protocols = None
    custom_protocols = None
    destination = None
    source = None

    send = False

    if session["extended_access"] == 'False':
        extended = False
    elif session["extended_access"] == 'True':
        extended = True
    else:
        extended = False

    command_config = []
    packet_list = ['dscp', 'eq', 'fragments', 'gt', 'log', 'log-input', 'lt', 'neq', 'option', 'precedence', 'range', 'time-range', 'tos']
    protokoller = ['ahp', 'eigrp', 'gre', 'icmp', 'igmp', 'ip', 'ipinip', 'nos', 'ospf', 'pcp', 'pim', 'tcp', 'udp']
    destinations = ['any', 'eq', 'gt', 'host', 'lt', 'neq', 'range']



    if request.method == 'POST':
        
        
        if request.form.get('extended_button'):
            extended = True
            session['extended_access'] = 'True'


        if request.form.get('standard_button'):
            extended = False
            session['extended_access'] = 'False'

        if request.form.get('save_button'):

            access_list_name = request.form.get('access_list_name')
            permit_or_deny = request.form.get('permit_or_deny')
            any_or_host = request.form.get('any_or_host')
            
            protocols = request.form.get('protocols')
            custom_protocols = request.form.get('custom_protocols')
            hostname = request.form.get('hostname')
            source = request.form.get('source')
            destination = request.form.get('destination')

            packet = request.form.get('packet')
            host_pis = request.form.get('host_pis')
            port = request.form.get('port')


             
            ### Extended access liste lavet ###
            if session['extended_access'] == 'True':
                command_config.append(f'ip access-list extended {access_list_name}')
                command_config.append(f'{permit_or_deny}')

                if custom_protocols != '':
                    command_config.append(f'{custom_protocols} {source} {destination}')

                else:
                    command_config.append(f'{protocols} {source} {destination}')
                

                if host_pis != None:
                    command_config.append(f'{host_pis}')
                    send = True
                
                elif port != None:
                    try:
                        port_int = int(port)
                        command_config.append(f'{port}')
                        send = True
                    except:
                        flash('Port kan kun være tal', category='error')
                    
                    
                else:
                    command_config.append(f'{packet}')
                    send = True
                    
                
                first_element = command_config[0]
                second_element = ' '.join(command_config[1:])
                command_config = [first_element, second_element]
                
                

            
            ### Standard access liste laves ###
            if session['extended_access'] == 'False':

                command_config.append(f'ip access-list standard {access_list_name}')

                if permit_or_deny == 'permit':
                    command_config.append(f'permit')
                else:
                    command_config.append(f'deny')


                if any_or_host == 'any':
                    
                    if hostname != '':
                        flash('Hostname skal være tomt, når "any" er valgt', category='error')

                    else:
                        command_config.append(any_or_host)
                        send = True

                else:
                    command_config.append(f'{any_or_host} {hostname}')
                    send = True

                first_element = command_config[0]
                second_element = ' '.join(command_config[1:])
                command_config = [first_element, second_element]
            
            print(command_config)
            
            
            if send == True:
                try:
                    connection = ConnectHandler(host=host, port=22,
                                                username=username, password=password,
                                                device_type='cisco_ios')
                    
                    output = connection.send_config_set(command_config)
                    save = connection.send_command('write memory')
                    print(output)
                    send = False

                except:
                    pass
        
        if request.form.get('next_button'):
            
            access_list_name = request.form.get('access_list_name')
            permit_or_deny = request.form.get('permit_or_deny')
            any_or_host = request.form.get('any_or_host')
            
            protocols = request.form.get('protocols')
            custom_protocols = request.form.get('custom_protocols')
            hostname = request.form.get('hostname')
            source = request.form.get('source')
            destination = request.form.get('destination')    

    return render_template('network_managing/access-list.html', 
                           user=current_user,  
                           network_name=network_name, 
                           host=host, 
                           username=username,
                           password=password,
                           extended=extended,
                           access_list_name=access_list_name,
                           hostname=hostname,
                           permit_or_deny=permit_or_deny,
                           protocols=protocols,
                           protokoller=protokoller,
                           source=source,
                           destination=destination,
                           destinations=destinations,
                           custom_protocols=custom_protocols,
                           any_or_host=any_or_host,
                           packet_list=packet_list
                           )

@network.route('/vlans', methods=['GET', 'POST'])
@login_required
def vlans():

    ## Netværk ###
    network_id = session["network_id"]
    network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    network_name = network.network_name
    host = network.host
    username = network.username
    password = network.password
   
    vlans = None
    selected_interface = None
    trunk_button = None
    access_button = None
    interfaces = None

    send = False

    command_config = []

    trunk_dropdown = ['encapsulation', 'nonegotiate', 'native', 'allowed']

    '''try:
        connection = ConnectHandler(host=host, port=22,
                                    username=username, password=password,
                                    device_type='cisco_ios')
                    
        vlans = connection.send_command('sh vlan br', use_textfsm=True)
        interfaces = connection.send_command('sh ip int br', use_textfsm=True)
        session["vlans"] = vlans
        session["interfaces"] = interfaces
        
        

    except:
        flash('Can\'t connect', category='error')'''

    if request.method == 'POST':


        vlan = request.form.get('vlan')
        vlan_name = request.form.get('vlan_name')

        switchport_mode = request.form.get('switchport_mode')
        selected_interface = request.form.get('interfaces')
        session["selected_interface"] = selected_interface

        trunk_options = request.form.get('trunk_options')
        trunk_user_input = request.form.get('trunk_user_input')
        vlan_switchport = request.form.get('vlan_switchport')
        

        
        


        if request.form.get('access_button'):
            access_button = True
            swp_mode = 'access'
            session["swp_mode"] = swp_mode
            
        
        elif request.form.get('trunk_button'):
            trunk_button = True
            swp_mode = 'trunk'
            session["swp_mode"] = swp_mode

        elif request.form.get('create_button'):
            command_config = [f'vlan {vlan}', f'name {vlan_name}']
            send = True
            
        elif request.form.get('send_button'):
            swp_mode = session["swp_mode"]
            command_config = [f'interface {selected_interface}', f'switchport mode {swp_mode}']
            
            if swp_mode == 'trunk':
            
                if trunk_options != '':
                    print('trunk er ikke none')
                    print(trunk_options)
                    command_config.append(f'{trunk_options} {trunk_user_input}')
            
            if swp_mode == 'access':
                
                command_config.append(vlan_switchport)
                
            send = True

        

        
            


        if send == True:
            first_element = command_config[0]
            second_element = ' '.join(command_config[1:])
            command_config = [first_element, second_element]
            print(command_config)
            try:
                connection = ConnectHandler(host=host, port=22,
                                    username=username, password=password,
                                    device_type='cisco_ios')
                    
                output = connection.send_config_set(command_config)
                print(output)
                send = False
        
            except:
                flash('Can\'t connect', category='error')
            




        


    
    return render_template('network_managing/vlans.html', 
                           user=current_user, 
                           vlans=vlans, 
                           interfaces=interfaces, 
                           selected_interface=selected_interface, 
                           access_button=access_button,
                           trunk_button=trunk_button,
                           trunk_dropdown=trunk_dropdown)

@network.route('/dhcp', methods=['GET', 'POST'])
@login_required
def dhcp():
    network_id = session["network_id"]
    routers = Routers.query.filter_by(user_id=current_user.id, networks=network_id).all()
    if request.method == 'POST':
        dhcp_name = request.form.get('dhcp_name')
        netværks_adresse = request.form.get('netværks_adresse')
        subnetmaske = request.form.get('subnetmaske')
        router = request.form.get('router')
        dns_server = request.form.get('dns_server')

        
    
    return render_template('network_managing/dhcp.html', user=current_user, routers=routers)

@network.route('/router', methods=['GET', 'POST'])
@login_required
def router():
    
    if request.method == 'POST':
        router_name = request.form.get('router_name')
        host = request.form.get('host')
        username = request.form.get('username')
        password = request.form.get('password')
        networks = session["network_id"]
        
        

        router = Routers.query.filter_by(user_id=current_user.id).count()
        router_id = int(router) + 1
        
        new_router = Routers(router_id=router_id, router_name=router_name, host=host, 
                               username=username, password=password, 
                               user_id=current_user.id, networks=networks)
        db.session.add(new_router)
        db.session.commit()

            

        flash('Router tilføjet!', category='success')
        return redirect(url_for('views.networks'))
    
    return render_template('network_managing/router.html', user=current_user)

@network.route('/ntp', methods=['GET', 'POST'])
@login_required
def ntp():
    network_id = session["network_id"]
    routers = Routers.query.filter_by(user_id=current_user.id, networks=network_id).all()

    if request.method == 'POST':
        stratum_number = request.form.get('stratum_number')
        tid = request.form.get('tid')
        klient = request.form.get('klient')

        

    return render_template('network_managing/ntp.html', user=current_user, routers=routers)

@network.route('/port-security', methods=['GET', 'POST'])
@login_required
def port_security():

    violations = ['shutdown', 'restrict', 'protect']
    
    if request.method == 'POST':
        interface = request.form.get('interface')
        maximum = request.form.get('maximum')
        mac = request.form.get('mac')
        violation = request.form.get('violation')

        


    return render_template('port_security.html', user=current_user, violations=violations)