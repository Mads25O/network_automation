from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, session
from flask_login import login_required, current_user
from .models import Networks
from . import db
import json

def handle_hostname(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    command_exec = [
        f'hostname {form.get("hostname")}',
    ]
    
    return command_exec

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

def handle_dhcp(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    command_exec = [
        f'ip dhcp excluded-address {form.get("exclude")}',
        f'ip dhcp pool {form.get("dhcp_name")}',
        f'network {form.get("netværks_adresse")}',
        f'default-router {form.get("network")}'
    ]
    

    return command_exec

def handle_ntp_klient(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    return [
        f'ntp server {form.get("server_ip")}'
    ]

def handle_ntp_server(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    return [
        f'ntp master {form.get("stratum_nummer")}',
        'ntp update-calendar',
        f'ntp server {form.get("server_ip")}'
    ]

def handle_port_security(method, form):
    if method != 'POST':
        return None
    
    if not form.get('create_button'):
        return None

    
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
        command_config.append(form.get("host_name"))
        command_config.append(form.get("wildcard"))
        command_config.append(form.get("source"))
    

    ### Standard access liste laves ###
    else:

        command = f'ip access-list standard {form.get("access_list_name")}'

        if form.get("permit_or_deny") == 'permit':
            command_config.append(f'permit')
        else:
            command_config.append(f'deny')

        if form.get("any_or_host") == 'any':
        
            command_config.append('any')

        else:
            command_config.append(f'host {form.get("hostname")}')
    
    command_exec = [command, ' '.join(command_config)]
    if form.get('ja_eller_nej'):
        command_exec.append('permit ip any any')
    command_exec.append(f'int {form.get("interface")}')
    command_exec.append(f'ip access-group {form.get("access_list_name")} {form.get("in_or_out")}')
    
    

    return command_exec