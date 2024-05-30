from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, session
from flask_login import login_required, current_user
from .models import Networks
from . import db
import json
from netmiko import ConnectHandler

views = Blueprint('views', __name__)

@views.route('/')
@login_required
def home():
    return render_template('home.html', user=current_user)

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
            return redirect(url_for('network.connect'))

        if request.form.get('create_network_button'):
            return redirect(url_for('network.create_network'))
            
    return render_template('networks.html', user=current_user)