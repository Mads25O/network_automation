from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, session
from flask_login import login_required, current_user
from .models import Note, Networks
from . import db
import json
from netmiko import ConnectHandler

views = Blueprint('views', __name__)

@views.route('/')
@login_required
def home():
    return render_template('home.html', user=current_user)

@views.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('Note is too short!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')

    return render_template('notes.html', user=current_user)

@views.route('/delete-note', methods=['POST'])
def delete_note():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
            
    return jsonify({})


@views.route('/create-network', methods=['GET', 'POST'])
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
        return redirect(url_for('views.manage_networks'))
    return render_template('create_network.html', user=current_user)

@views.route('/manage-network', methods=['GET', 'POST'])
@login_required
def manage_networks():
    if request.method == 'POST':

        if request.form.get('change_button'):

            network_id = request.form['change_button']
            
            #network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
            
            session["network_id"] = network_id
            #session["network_name"] = network.network_name
            #session["host"] = network.host
            #session["username"] = network.username
            #session["password"] = network.password

            return redirect(url_for('views.edit_network'))
        
        if request.form.get('connect_button'):
            network_id = request.form['connect_button']
            
            session["network_id"] = network_id
            network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
            host = network.host
            username = network.username
            password = network.password

            
            try:
                connection = ConnectHandler(host=host, port=22,
                                        username=username, password=password,
                                        device_type='cisco_ios')
                output = connection.send_command('sh ip int brief')

                print(output)
                return redirect(url_for('views.connect'))
            
            except:
                flash('Can\'t connect', category='error')

        if request.form.get('access_button'):

            network_id = request.form['access_button']
            session["network_id"] = network_id
            session["extended_access"] = 'False'

            return redirect(url_for('views.access_list'))
        
        if request.form.get('vlan_button'):

            network_id = request.form['vlan_button']
            session["network_id"] = network_id
            network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
            host = network.host
            username = network.username
            password = network.password

            try:
                connection = ConnectHandler(host=host, port=22,
                                        username=username, password=password,
                                        device_type='cisco_ios')
                vlans = connection.send_command('sh vlan br')

                print(vlans)
                return redirect(url_for('views.vlans'))
            
            except:
                flash('Can\'t connect', category='error')

        
        if request.form.get('dhcp_button'):

            ### Netværk ###
            network_id = request.form['dhcp_button']
            session["network_id"] = network_id
            network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
            host = network.host
            username = network.username
            password = network.password

            return redirect(url_for('views.dhcp'))

            

        
    return render_template('manage_networks.html', user=current_user)


@views.route('/edit-network', methods=['GET', 'POST'])
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
            return redirect(url_for('views.manage_networks'))

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
                

            return redirect(url_for('views.manage_networks'))
        
    return render_template('edit_network.html', user=current_user, network_name=network_name, host=host, username=username, password=password)


@views.route('/connect', methods=['GET', 'POST'])
@login_required
def connect():
    network_id = session["network_id"]
    network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    network_name = network.network_name
    host = network.host
    username = network.username
    password = network.password


    #user_input = request.form.get('command')
    connection = ConnectHandler(host=host, port=22,
                                username=username, password=password,
                                device_type='cisco_ios')
        
    
        
    output = connection.send_command(f'sh ip int br', use_textfsm=True)

    if request.method == 'POST':
        vlan_id = '20'
        vlan_name = 'Orders'

        config_commands = [
            f'vlan {vlan_id}',
            f'name {vlan_name}',
            f'interface vlan {vlan_id}',
            f'ip address 192.168.100.120 255.255.255.0'
        ]

        connection.send_config_set(config_commands)
        connection.send_command('write memory')
        connection.disconnect()

        return redirect(url_for('views.connect'))
    
    return render_template('connect.html', 
                           user=current_user, 
                           network_name=network_name, 
                           host=host, username=username, 
                           password=password, 
                           output=output)

@views.route('/access-list', methods = ['GET', 'POST'])
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
    packet_list = []


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
            

            

            if destination == 'any_dest':
                packet_list = ['dscp', 'eq', 'fragments', 'gt', 'log', 'log-input', 'lt', 'neq', 'option', 'precedence', 'range', 'time-range', 'tos']
            
            elif destination == 'host':
                packet_list = []
        

        

    

    return render_template('access-list.html', 
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
                           source=source,
                           destination=destination,
                           custom_protocols=custom_protocols,
                           any_or_host=any_or_host,
                           packet_list=packet_list)

@views.route('/vlans', methods=['GET', 'POST'])
@login_required
def vlans():

    ### Netværk ###
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

    try:
        connection = ConnectHandler(host=host, port=22,
                                    username=username, password=password,
                                    device_type='cisco_ios')
                    
        vlans = connection.send_command('sh vlan br', use_textfsm=True)
        interfaces = connection.send_command('sh ip int br', use_textfsm=True)
        session["vlans"] = vlans
        session["interfaces"] = interfaces
        
        

    except:
        flash('Can\'t connect', category='error')

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
            '''try:
                connection = ConnectHandler(host=host, port=22,
                                    username=username, password=password,
                                    device_type='cisco_ios')
                    
                output = connection.send_config_set(command_config)
                print(output)
                send = False
        
            except:
                flash('Can\'t connect', category='error')'''
            




        


    
    return render_template('vlans.html', 
                           user=current_user, 
                           vlans=vlans, 
                           interfaces=interfaces, 
                           selected_interface=selected_interface, 
                           access_button=access_button,
                           trunk_button=trunk_button,
                           trunk_dropdown=trunk_dropdown)

@views.route('/dhcp')
@login_required
def dhcp():
    return render_template('dhcp.html', user=current_user)