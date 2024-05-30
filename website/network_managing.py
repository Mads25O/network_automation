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
        return redirect(url_for('views.networks'))
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
            flash('Network deleted', category='success')
            return redirect(url_for('views.networks'))
        

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
                

            return redirect(url_for('views.networks'))
        
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
    
    if request.form.get('hostname_button'):
        return redirect(url_for('network.hostname'))

    if request.form.get('access_button'):

        network_id = request.form['access_button']
        session["network_id"] = network_id
        session["extended_access"] = 'False'
        return redirect(url_for('network.access_list'))
        
    if request.form.get('vlan_button'):
        return redirect(url_for('network.vlans'))

    if request.form.get('dhcp_button'):
        return redirect(url_for('network.dhcp'))

    if request.form.get('router_button'):
        return redirect(url_for('network.router'))
    
    if request.form.get('ntp_server_button'):
        return redirect(url_for('network.ntp_server'))
    
    if request.form.get('ntp_klient_button'):
        return redirect(url_for('network.ntp_klient'))
    
    if request.form.get('port_sec_button'):
        return redirect(url_for('network.port_security'))

    if request.form.get('gem_button'):
        remote_execute('wr', session, Networks)
        flash('Gemt!', category='success')
        
    
    return render_template('network_managing/connect.html', 
                           user=current_user, 
                           network_name=network_name, 
                           host=host, username=username, 
                           password=password, 
                           interfaces=interfaces,
                           vlans=vlans
                           )

@network.route('/hostname', methods = ['GET', 'POST'])
@login_required
def hostname():
    
    result = handle_hostname(request.method, request.form)
    if result == None:
        # Tager alle form nøgler og pakker dem ud som en key value pair arg
        return render_template('network_managing/hostname.html', 
                            user=current_user, **request.form)
    
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))

def handle_hostname(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    command_exec = [
        f'hostname {form.get("hostname")}',
    ]
    

    return command_exec

@network.route('/access-list', methods = ['GET', 'POST'])
@login_required
def access_list():

    if request.form.get('extended_button'):
            session['extended_access'] = True

    if request.form.get('standard_button'):
            session['extended_access'] = False

    result = handle_access_list(request.method, request.form, session)
    if result == None:
        # Tager alle form nøgler og pakker dem ud som en key value pair arg
        return render_template('network_managing/access-list.html', 
                            user=current_user, **request.form, **session)
    
    remote_execute(result, session, Networks)
    # redirect til noget

    return redirect(url_for('network.connect'))

@network.route('/vlans', methods=['GET', 'POST'])
@login_required
def vlans():
    result = handle_vlan(request.method, request.form, session)

    if result == None:
        return render_template('network_managing/vlans.html', 
                            user=current_user, **request.form,session=session)
    
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))

def handle_vlan(method, form, session):

    if session.get("swp_mode", None):
        swp_mode = ''


    command_config = []

    if method != 'POST':
        return None
    
    if request.form.get('access_button'):
        session["swp_mode"] = 'access'
        return None
            
    if request.form.get('trunk_button'):
        session["swp_mode"] = 'trunk'
        return None
    if request.form.get('create_button'):
        return [f'vlan {form.get("vlan")}', f'name {form.get("vlan_name")}']
    
    command_config = [
        f'interface {form.get("interfaces")}',
        f'switchport mode {session.get("swp_mode")}'
        ]

    if session.get("swp_mode",'')  == 'trunk' and form.get("trunk_options", '') != '':
        command_config.append(f'switchport trunk {form.get("trunk_options")} vlan {form.get("trunk_options_two")} {form.get("trunk_user_input")}')
    
    else:
        command_config.append(f'switchport access vlan {form.get("vlan_switchport")}')
    
    return command_config

@network.route('/dhcp', methods=['GET', 'POST'])
@login_required
def dhcp():
    network_id = session["network_id"]
    routers = Routers.query.filter_by(user_id=current_user.id, networks=network_id).all()

    result = handle_dhcp(request.method, request.form)
    if result == None:
        # Tager alle form nøgler og pakker dem ud som en key value pair arg
        return render_template('network_managing/dhcp.html', 
                            user=current_user, routers=routers, **request.form)
    remote_execute(result, session, Networks)
    return redirect(url_for('network.connect'))

def handle_dhcp(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    command_exec = [
        f'ip dhcp pool {form.get("dhcp_name")}',
        f'network {form.get("netværks_adresse")}',
        f'dns-server {form.get("dns_server")}',
        f'default-router {form.get("network")}',
        f'domain-name {form.get("domain")}',
        f'lease {form.get("lease")}'
    ]
    

    return command_exec

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

@network.route('/ntp-klient', methods=['GET', 'POST'])
@login_required
def ntp_klient():
    network_id = session["network_id"]
    routers = Routers.query.filter_by(user_id=current_user.id, networks=network_id).all()        

    result = handle_ntp_klient(request.method, request.form)
    if result == None:
        # Tager alle form nøgler og pakker dem ud som en key value pair arg
        return render_template('network_managing/ntp_klient.html', 
                            user=current_user, routers=routers, **request.form)
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))


def handle_ntp_klient(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    return [
        f'ntp server {form.get("server_ip")}',
        f'ntp update-calendar'
    ]

@network.route('/ntp-server', methods=['GET', 'POST'])
@login_required
def ntp_server():
    network_id = session["network_id"]
    routers = Routers.query.filter_by(user_id=current_user.id, networks=network_id).all()

    result = handle_ntp_server(request.method, request.form)
    if result == None:
        # Tager alle form nøgler og pakker dem ud som en key value pair arg
        return render_template('network_managing/ntp_server.html', 
                            user=current_user, routers=routers, **request.form)
    
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))



def handle_ntp_server(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    return [
        f'ntp master {form.get("stratum_nummer")}',
        f'ntp source {form.get("server_ip")}'
    ]

@network.route('/port-security', methods=['GET', 'POST'])
@login_required
def port_security():
    
    result = handle_port_security(request.method, request.form)
    if result == None:
        # Tager alle form nøgler og pakker dem ud som en key value pair arg
        return render_template('network_managing/port_security.html', 
                            user=current_user, **request.form, **session)
    
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))

def handle_port_security(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    # Sikre man in the middle attack
    return [
        f'interface range {form.get("from_interface")} - {form.get("to_interface")}',
        'switchport port-security',
        'switchport port-security maximum 2',
        'switchport port-security mac-address sticky',
        'switchport port-security violation shutdown'
        ]


def handle_access_list(method, form, session):
    if method != 'POST':
        return None
    
    if not form.get('save_button'):
        return None

    if session.get("extended_access", False):
        extended = 'true'
    else:
        extended = 'false'

    command = ''
    command_config = []



            
    ### Extended access liste lavet ###
    if session.get('extended_access', False):
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
                return None
            
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

    command_exec = [command, ' '.join(command_config)]
    
    print(command_exec)

    return command_exec



    
    
def remote_execute(command, session, networks):

    network_id = session["network_id"]
    network = networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    host = network.host
    username = network.username
    password = network.password

    print(command)

    try:
        connection = ConnectHandler(host=host, port=22,
                                    username=username, password=password,
                                    device_type='cisco_ios')
        
        output = connection.send_config_set(command)
        # connection.send_command('write memory')
        print(output)

    except:
        flash('Blev ikke sendt til netværket, da der opstod problemer.', category='error')