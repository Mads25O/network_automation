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


@views.route('/networks', methods=['GET', 'POST'])
@login_required
def networks():

    if request.method == 'POST':

        if request.form.get('change_button'):
            network_id = request.form['change_button']
            session["network_id"] = network_id
            return redirect(url_for('network.edit_network'))
        
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
                return redirect(url_for('network.connect'))
            
            except:
                flash('Can\'t connect', category='error')

        if request.form.get('access_button'):

            network_id = request.form['access_button']
            session["network_id"] = network_id
            session["extended_access"] = 'False'

            return redirect(url_for('network.access_list'))
        
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
                return redirect(url_for('network.vlans'))
            
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

            return redirect(url_for('network.dhcp'))

        if request.form.get('create_network_button'):
            return redirect(url_for('network.create_network'))
            
    return render_template('networks.html', user=current_user)