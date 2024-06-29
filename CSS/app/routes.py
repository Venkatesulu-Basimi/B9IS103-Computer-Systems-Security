from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash


import os
import logging
import re


@main.route('/')
def index():
    if 'username' in session:
        if session.get('is_admin'):
            return redirect(url_for('main.admin_dashboard'))
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))