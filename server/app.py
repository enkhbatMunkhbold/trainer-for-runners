from flask import request
from flask_restful import Resource

from config import app, db, api
from models import User, Route, Style, Program

@app.route('/')
def index():
    return '<h1>Project Server</h1>'


if __name__ == '__main__':
    app.run(port=5555, debug=True)

