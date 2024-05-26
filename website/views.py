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
    output = None

    if request.method == 'POST':

        user_input = request.form.get('command')
        connection = ConnectHandler(host=host, port=22,
                                        username=username, password=password,
                                        device_type='cisco_ios')
        
        try:
        
            output = connection.send_command(f'{user_input}', use_textfsm=True)

        except:
            flash('Command traceback', category='error')


    
    return render_template('connect.html', user=current_user, network_name=network_name, host=host, username=username, password=password, output=output)
