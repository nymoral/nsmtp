# Copyright (c) 2015, Aivaras Saulius
# All rights reserved.

from nsmtp import *
import getpass

def send_test():
    username = "aivaras.saulius@gmail.com"
    password = getpass.getpass("Password: ")

    user = User(username, password)

    sender = username
    to_list = ["aivaras.saulius@outlook.com"]
    subject = "Email subject"
    body = """Hello, there!\nHow's it hangin'?\r\n.\r\n^  This dot should be visable."""

    body = format_message_body(sender, to_list, subject, body)
    msg = Message(sender, to_list, body)

    s = None
    try:
        s = MailSender('smtp.gmail.com', 465, debug=True)
    except MailError as e:
        print(e)
        return
        
    with s:
        try:
            s.authenticate(user)
            s.send_message(msg)
        except MailError as e:
            print(e)
            return

if __name__ == "__main__":
    send_test()

