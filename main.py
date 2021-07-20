from flask import Flask
from flask_restful import Api

from controllers.whois_api import WhoIs

app = Flask(__name__)
api = Api(app)

api.add_resource(WhoIs, "/whois")

if __name__ == "__main__":
    app.run()
