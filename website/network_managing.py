from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_required, current_user
from .models import Networks
from .handles import handle_hostname, handle_vlan, handle_dhcp, handle_ntp_klient, handle_ntp_server, handle_port_security, handle_access_list
from . import db
from netmiko import ConnectHandler

network = Blueprint('network', __name__, template_folder='templates/network_managing')

@network.route('/create-network', methods=['GET', 'POST'])
@login_required
def create_network():

    if request.method != 'POST':
        return render_template('create_network.html', user=current_user)

    
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
        flash('Kan ikke forbinde', category='error')
    
    vlans = session["vlans"]
    interfaces = session["interfaces"]
    
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
        connection.send_command('write memory')

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
        return render_template('network_managing/hostname.html', 
                            user=current_user, **request.form)
    
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))

@network.route('/access-list', methods = ['GET', 'POST'])
@login_required
def access_list():

    if request.form.get('extended_button'):
            session['extended_access'] = True

    if request.form.get('standard_button'):
            session['extended_access'] = False

    result = handle_access_list(request.method, request.form, session)
    if result == None:
        
        return render_template('network_managing/access-list.html', 
                            user=current_user, **request.form, **session)
    
    remote_execute(result, session, Networks)
    

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

@network.route('/dhcp', methods=['GET', 'POST'])
@login_required
def dhcp():
    result = handle_dhcp(request.method, request.form)
    if result == None:
        
        return render_template('network_managing/dhcp.html', 
                            user=current_user, **request.form)
    remote_execute(result, session, Networks)
    return redirect(url_for('network.connect'))

@network.route('/ntp-klient', methods=['GET', 'POST'])
@login_required
def ntp_klient():  
    result = handle_ntp_klient(request.method, request.form)
    if result == None:
        
        return render_template('network_managing/ntp_klient.html', 
                            user=current_user, **request.form)
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))

@network.route('/ntp-server', methods=['GET', 'POST'])
@login_required
def ntp_server():
    result = handle_ntp_server(request.method, request.form)
    if result == None:
        
        return render_template('network_managing/ntp_server.html', 
                            user=current_user, **request.form)
    
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))

@network.route('/port-security', methods=['GET', 'POST'])
@login_required
def port_security():
    
    result = handle_port_security(request.method, request.form)
    if result == None:
        
        return render_template('network_managing/port_security.html', 
                            user=current_user, **request.form, **session)
    
    remote_execute(result, session, Networks)

    return redirect(url_for('network.connect'))
    
    
def remote_execute(command, session, networks):

    network_id = session["network_id"]
    network = networks.query.filter_by(user_id=current_user.id, network_id=network_id).first()
    host = network.host
    username = network.username
    password = network.password

    print(command)

    '''try:
        connection = ConnectHandler(host=host, port=22,
                                    username=username, password=password,
                                    device_type='cisco_ios')
        
        output = connection.send_config_set(command)
        print(output)   

    except:
        flash('Blev ikke sendt til netværket, da der opstod problemer.', category='error')'''