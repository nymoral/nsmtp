# Copyright (c) 2015, Aivaras Saulius
# All rights reserved.

from flask import Flask
from flask import render_template
from flask import request

import os

from nsmtp import *

app = Flask(__name__)


class EmailForm(object):

    def __init__(self, form):
        self.from_email = form.get("from_email", "")
        self.to_email = form.get("to_email", "")
        self.subject = form.get("subject", "")
        self.message = form.get("message", "")
        self.server_name = form.get("server_name", "")
        self.port = form.get("port", "")
        self.username = form.get("username", "")
        self.password= form.get("password", "")
        self.error_message = None


    def get_dict(self):
        return self.__dict__


    def need_auth(self):
        return self.username != ""


    def set_message(self, message):
        self.error_message = message


def make_sender(server, port):
    try:
        s = MailSender(server, port, debug=False)
        return (None, s)
    except MailError as e:
        return (str(e), None)
    except Exception as e:
        return ("Internal error nr 1 (" + str(e) + ")", None)


def send_mail(f):
    sender = f.from_email
    to_list = [f.to_email]
    body = format_message_body(sender, to_list, f.subject, f.message)
    msg = Message(sender, to_list, body)

    res = make_sender(f.server_name, int(f.port))
    if res[0]:
        return res[0]
    s = res[1]

    with s:
        try:
            if f.need_auth():
                u = User(f.username, f.password)
                s.authenticate(u)
            s.send_message(msg)
        except AuthError as e:
            return "Authentiction failed"
        except AuthRequired as e:
            return "Authentiction required"
        except MailError as e:
            return str(e)
        except Exception as e:
            return "Internal error nr 2 (" + str(e) + ")"

    return None


def generate_get():
    return render_template("home.html")


def generate_post():
    f = EmailForm(request.form)
    e = send_mail(f)
    if e:
        f.set_message(e)
    else:
        return render_template("home.html", success=True)
    return render_template("home.html", **f.get_dict())


@app.route("/", methods=['POST', 'GET'])
def home():
    if request.method == "POST":
        return generate_post()
    else:
        return generate_get()


if __name__ == "__main__":
    app.run()

