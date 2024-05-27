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
            network_name = network.network_name
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

    network_id = session["network_id"]
    network = Networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    network_name = network.network_name
    host = network.host
    username = network.username
    password = network.password

    access_list_name = None
    hostname = None
    permit_or_deny = None
    any_or_host = None
    protocols = None
    custom_protocols = None
    destination = None
    source = None

    if session["extended_access"] == 'False':
        extended = False

    if session["extended_access"] == 'True':
        extended = True

    if session["extended_access"] == 'None':
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
            ip_or_port = request.form.get('ip_or_port')

            permit_or_deny = request.form.get('permit_or_deny')
            any_or_host = request.form.get('any_or_host')
            
            protocols = request.form.get('protocols')
            custom_protocols = request.form.get('custom_protocols')
            hostname = request.form.get('hostname')
            source = request.form.get('source')
            destination = request.form.get('destination')

            packet = request.form.get('packet')
            host_pis = request.form.get('host')
            port = request.form.get('port')


            #print(access_list_name, permit_or_deny, any_or_host, protocols, custom_protocols, hostname, source)
             
            
            if session['extended_access'] == 'True':
                command_config.append(f'ip access-list extended {access_list_name}')
                command_config.append(f'{permit_or_deny}')

                if custom_protocols != '':
                    command_config.append(f'{custom_protocols} {source} {destination}')
                else:
                    command_config.append(f'{protocols} {source} {destination}')
                

                if host_pis != '':
                    command_config.append(f'{host_pis}')
                elif port != '':
                    command_config.append(f'{port}')
                else:
                    command_config.append(f'{packet}')
                
                print(command_config)
            

            if session['extended_access'] == 'False':

                command_config.append(f'ip access-list standard {access_list_name}')

                if permit_or_deny == 'permit':
                    command_config.append(f'permit {ip_or_port}')
                else:
                    command_config.append(f'deny {ip_or_port}')
            
            '''if type == 'ip':
                command_config.append('ip')
            else:
                command_config.append('port')'''

            

            '''try:
                connection = ConnectHandler(host=host, port=22,
                                            username=username, password=password,
                                            device_type='cisco_ios')
                
                #output = connection.send_config_set(command_config)
                #save = connection.send_command('write memory')
                #print(output)

            except:
                pass'''
        
        if request.form.get('next_button'):
            
            access_list_name = request.form.get('access_list_name')
            action = request.form.get('action')
            ip_or_port = request.form.get('ip_or_port')

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

@views.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    action = request.form.get('action')
    if action == 'permit':
        print("Permit was selected.")
    elif action == 'deny':
        print("Deny was selected.")
    elif action == 'ip':
        print('IP was selected')
    elif action == 'port':
        print('Port was selected')
    else:
        print("No valid selection was made.")
    

    
