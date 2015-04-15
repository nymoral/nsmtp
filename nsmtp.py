# Copyright (c) 2015, Aivaras Saulius
# All rights reserved.

import ssl
import socket
import base64

import signal

from sys import stderr

# Some exceptions:

class MailError(Exception):
    def __init__(self, *args):
        super(Exception, self).__init__(" ".join(str(v) for v in args))


class AuthError(MailError):
    pass


class AuthRequired(MailError):
    pass


class TimeoutError(MailError):
    pass


def new_smtp_connection(host, port, timeout=4):

    """ Try to make a TCP connection to host:port.
        Returns socket.socket (ssl.SSLSocket with ssl, but they're compatable). """

    def handle_timeout(signum, frame):
        raise TimeoutError("Connection timed out on me")

    cl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx = ssl.create_default_context()
    cl = ctx.wrap_socket(cl, server_hostname=host)
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.alarm(timeout)
    try:
        cl.connect((host, int(port)))
    except Exception as e:
        raise MailError("Connection error", str(e))
    finally:
        signal.alarm(0)
    return cl


class ClientCommand(object):

    """ SMTP Client message."""
        
    def __init__(self, command, *args):
        """ Example:
            ClientCommand("AUTH", "PLAIN").generate() == "AUTH PLAIN" """
        self.generated = None
        self.command = command
        if len(args) == 0:
            self.args = None
        else:
            self.args = args


    def __generate_str_command(self):
        if self.args is None:
            return self.command
        if self.args == None:
            return self.command
        return self.command + " " + " ".join(self.args)


    def generate(self):
        if self.generated is None:
            self.generated = self.__generate_str_command()
        return self.generated


    def __str__(self):
        return self.generate()


class ServerResponse(object):

    """ SMTP Server message.
        It always begins with a code 
        (sometimes folowed by a dash(-),
            which means server will send another message),
        and possibly server's comment. """

    def __init__(self, line):
        self.code = None
        self.message = []
        self.will_continue=False
        line = line.split(' ')
        if len(line) > 0:
            self.code = line[0]
            l = self.code.split("-")
            if (len(l) > 1):
                self.will_continue = True
                self.code = l[0]
                self.message.append("-".join(l[1:]))
        if len(line) > 1:
            self.message.extend(line[1:])


    def __str__(self):
        return "[{}] {} {}".format(self.will_continue, self.code, self.comment())


    def comment(self):
        return " ".join(self.message)


class SMTPSession(object):

    """ Single SMTP session.
        Represents a single TCP connection.
        Possible to perform multiple transactions with one session """

    cmd_quit        = ClientCommand("QUIT")
    cmd_ehlo        = ClientCommand("EHLO")
    cmd_auth_plain  = ClientCommand("AUTH", "PLAIN")
    cmd_data        = ClientCommand("DATA")
    cmd_end_data    = ClientCommand(".")


    def __init__(self, conn, debug=False):
        self.conn = conn
        self.debug = debug
        self.conn_file = conn.makefile('r', encoding="ASCII", newline='\r\n')
        self.options = {}


    def dprint(self, *args):
        if self.debug:
            print("DEBUG:", *args, file = stderr)


    def read_crlf_line(self):
        line = self.conn_file.readline()
        if len(line) < 2:
            return None
        if line[-1] != '\n' or line[-2] != '\r':
            return None
        r = line[:-2]
        self.dprint("S:", r)
        return r


    def get_response(self):
        return ServerResponse(self.read_crlf_line())


    def ignore_responses(self, resp = None):
        if resp == None:
            while self.get_response().will_continue:
                pass
        else:
            while resp.will_continue:
                resp = self.get_response()


    def send_line(self, msg):
        self.dprint("C:", msg)
        self.conn.write(bytes(msg + '\r\n', 'ASCII'))


    def send_command(self, cmd):
        self.send_line(cmd.generate())


    def start_session(self):
        greet = self.get_response()
        self.ignore_responses(greet)


    def quit_session(self):
        self.send_command(self.cmd_quit)
        self.ignore_responses()
        self.conn.close()


    def fill_options(self, message):
        l = len(message)
        if l == 0:
            return
        key = message[0].upper()
        value = message[1:]
        self.options[key] = value

            
    def identify_client(self):
        self.send_command(self.cmd_ehlo)
        resp = self.get_response()
        # First response is not interesting - it just verifies that we're talking with the same
        # server.
        if resp.code != "250":
            raise MailError(resp.code, resp.comment())
        while resp.will_continue:
            # This will be more interesting:
            # We need to extract auth methods.
            resp = self.get_response()
            if resp.code != "250":
                raise MailError(resp.code, resp.comment())
            self.fill_options(resp.message)


    def prep_send(self, msg):
        cmd = ClientCommand("MAIL", msg.formated_sender()) 
        self.send_command(cmd)
        resp = self.get_response()
        code = resp.code
        self.ignore_responses(resp)
        if code != "250":
            raise AuthRequired("Authentication required.", resp.comment())


    def build_plain_auth_message(self, u, p):
        enc_username = bytearray(u, "ASCII")
        enc_password = bytearray(p, "ASCII")
        full_message = bytearray()
        full_message.extend(enc_username)
        full_message.append(0x00)
        full_message.extend(enc_username)
        full_message.append(0x00)
        full_message.extend(enc_password)
        s = base64.b64encode(full_message)
        return str(s, "ASCII")


    def auth_plain(self, u, p):
        self.send_command(self.cmd_auth_plain)
        resp = self.get_response()
        code = resp.code
        self.ignore_responses(resp)
        if code != "334":
            raise MailError("Authentication method not supported.", resp.comment)
        s = self.build_plain_auth_message(u, p)
        self.send_line(s)
        resp = self.get_response()
        code = resp.code
        self.ignore_responses(resp)
        if code == "535":
            raise AuthError("Authentication failed.", resp.comment())


    def pick_authenticator(self, methods):
        if "PLAIN" in methods:
            return self.auth_plain
        return None


    def authenticate(self, user):

        methods = self.options.get("AUTH")
        if methods == None:
            raise MailError("Server did not provide me with a list of acceppted authentication options")

        authenticator = self.pick_authenticator(methods)
        if authenticator == None:
            raise MailError("I don't know how to authenticate with this server")

        authenticator(user.username, user.password)


    def send_recipients(self, msg):
        for rcpt in msg.formated_rcpt_iter():
            cmd = ClientCommand("RCPT", rcpt)
            self.send_command(cmd)
            resp = self.get_response()
            self.ignore_responses(resp)
            if resp.code != "250":
                raise MailError("Failed to send recipients", resp.comment())
            

    def send_body(self, msg):
        self.send_command(self.cmd_data)
        self.ignore_responses()
        for line in msg.formated_body_line_iter():
            self.send_line(line)
        self.send_line(".")
        resp = self.get_response()
        code = resp.code
        self.ignore_responses(resp)



class User(object):

    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password

class Message(object):

    def __init__(self, sender, to_list, body):
        if len(to_list) == 0:
            raise MailError("No recipients")
        self.sender = sender
        self.to_list = to_list
        self.body = body

    def formated_sender(self):
        return "FROM:" + self.sender.join("<>")

    def formated_rcpt_iter(self):
        for t in self.to_list:
            yield "TO:" + t.join("<>")

    def escaped_body(self):
        return self.body.replace('\n.', '\n..')

    def formated_body_line_iter(self):
        return iter(self.escaped_body().splitlines())


def format_message_body(sender, to_list, subject, body):
    r = "FROM: " + sender + "\r\n"
    for t in to_list:
        r+= "To: " + t + "\r\n"
    r += "Subject: " + subject + "\r\n\r\n"
    r += body
    return r


class MailSender(object):

    """ SMTP Email sending session.
        Every session must begin with start() (or python's with statement),
        and end with exit() (not needed if using with statement).
        Single call to authenticate is enough.
        Raises these exceptions:
            * Constructor can raise MailError if it fails to open TCP connection.
            * start(), send_message() and authenticate() calls can raise MailError if 
                client receives unexpected response (can occur due to misformated data when sending mail.
                Also, this exception can indicate client's incompatability with server (authenticatin method mismach for example).
            * send_message() can raise AuthRequired if server requires authentication, of send_message was called with failed authentication.
            * authenticate() call can raise AuthError if authentication fails.
        Exception sometimes includes first line of servers comment.
        """

    def __init__(self, host, port, debug=False):
        self.session = SMTPSession(new_smtp_connection(host, port), debug)
        self.session_started = False


    def start(self):
        if not self.session_started:
            self.session.start_session()
            self.session.identify_client()
        self.session_started = True
        return self


    def __enter__(self):
        self.start()
        return self


    def exit(self):
        self.session.quit_session()


    def __exit__(self, type, value, e):
        self.exit()


    def send_message(self, msg):
        self.session.prep_send(msg)
        self.session.send_recipients(msg)
        self.session.send_body(msg)


    def authenticate(self, user):
        self.session.authenticate(user)
        return self


