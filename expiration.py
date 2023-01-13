#!/usr/bin/python

import string
import whois
from datetime import datetime
from sys import argv,exit
import smtplib
from email.message import EmailMessage
from datetime import datetime
import logging

now = datetime.now()

domainFile = open('domains.txt', 'r')

def sendMail(content, subject):
    msg = EmailMessage()
    msg.set_content(content)

    msg['Subject'] = subject + ' Domain Expiration'
    msg['From'] = '' #Email From
    msg['To'] = '' #Email Destination

    mailserver = smtplib.SMTP('smtp.office365.com',587)
    mailserver.ehlo()
    mailserver.starttls()
    mailserver.login('', '') #add username, password

    mailserver.send_message(msg)
    mailserver.quit()

def logError(error, domain):
    now = datetime.now()
    timeStamp = datetime.timestamp(now)

    f = open("log.txt", "a")
    f.write(timeStamp + " " + domain + " "  + str(error))
    f.write("------------------------------------------")
    f.close()


while True:
        domain = domainFile.readline()
        domain = domain.strip("\n")
        print(domain)
        if not domain:
            break

        try:
            w = whois.whois(domain)
        except whois.parser.PywhoisError as e:
            print (e)
            exit(1)

        if type(w.expiration_date) == list:
            w.expiration_date = w.expiration_date[0]
        else:
            w.expiration_date = w.expiration_date 


        try:
            domain_expiration_date = str(w.expiration_date.day) + '/' + str(w.expiration_date.month) + '/' + str(w.expiration_date.year)

            timedelta = w.expiration_date - now
            days_to_expire = timedelta.days


            if timedelta.days <= 30 and timedelta.days > 10:
                msg =  'WARNING:' + domain + ' is going to expire in ' + str(timedelta.days) + ' days, expiration date is set to ' + domain_expiration_date
                sendMail(msg, 'WARNING:')
            elif timedelta.days <= 10:
                msg =  'CRITICAL:' + domain + ' is going to expire in ' + str(timedelta.days) + ' days, expiration date is set to ' + domain_expiration_date
                sendMail(msg, 'CRITICAL:')

        except Exception as e:
            logError(e,domain)





