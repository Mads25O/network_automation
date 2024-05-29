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

    

    dropdown_dict = {
        'packet_list' : ['dscp', 'eq', 'fragments', 'gt', 'log', 'log-input', 'lt', 'neq', 'option', 'precedence', 'range', 'time-range', 'tos'],
        'protokoller' : ['ahp', 'eigrp', 'gre', 'icmp', 'igmp', 'ip', 'ipinip', 'nos', 'ospf', 'pcp', 'pim', 'tcp', 'udp'],
        'destinations' : ['any', 'eq', 'gt', 'host', 'lt', 'neq', 'range']
    }

    if request.form.get('extended_button'):
            session['extended_access'] = True

    if request.form.get('standard_button'):
            session['extended_access'] = False

    #handle_access_list(request.method, request.form, session)
    # Tager alle form nøgler og pakker dem ud som en key value pair arg
    print(request.form)
    return render_template('network_managing/access-list.html', 
                           **request.form, **dropdown_dict, **session)

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


def handle_access_list(method, form, session):
    # Netværk


    if method != 'POST':
        return
    
    if not form.get('save_button'):
        return
    
    network_id = session["network_id"]
    network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()

    send = False

    if session["extended_access"] == 'False':
        extended = False
    elif session["extended_access"] == 'True':
        extended = True
    else:
        extended = False

    command = ''
    command_config = []

            
    ### Extended access liste lavet ###
    if session['extended_access'] == 'True':
        protocols = form.get("protocols")
        if form.get("custom_protocols") != '':
            protocols = form.get("custom_protocols")

        command = f'ip access-list extended {form.get("access_list_name")}'
        command_config.append(form.get("permit_or_deny"))
        command_config.append(protocols)
        command_config.append(form.get("source"))
        command_config.append(form.get("destination"))

        if form.get("host_pis") != None:
            command_config.append(f'{form.get("host_pis")}')
            
        
        elif form.get("port") != None:
            try:
                port_int = int(form.get("port"))
                command_config.append(str(port_int))
                
            except:
                flash('Port kan kun være tal', category='error')
        # To-do return abort
            
        else:
            command_config.append(f'{form.get("packet")}')
    

    ### Standard access liste laves ###
    else:

        command = f'ip access-list standard {form.get("access_list_name")}'

        if form.get("permit_or_deny") == 'permit':
            command_config.append(f'permit')
        else:
            command_config.append(f'deny')

        # Source i HTML
        if form.get("any_or_host") == 'any':
        
            command_config.append('any')

        else:
            command_config.append(f'host {form.get("hostname")}')

    print(command_config)
    command_exec = [command, ' '.join(command_config)]
    
    print(command_exec)
    
    
    '''if send == True:
        try:
            connection = ConnectHandler(host=host, port=22,
                                        username=username, password=password,
                                        device_type='cisco_ios')
            
            output = connection.send_config_set(command_config)
            save = connection.send_command('write memory')
            print(output)
            send = False

        except:
            pass'''