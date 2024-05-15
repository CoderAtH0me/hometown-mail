# -*- coding: utf-8 -*-

import logging
import socket
import base64
import hashlib
import time
import dateutil
import lxml
import re
import numbers


from lxml import etree
from markupsafe import Markup, escape

from socket import gaierror, timeout
from odoo import api, fields, models, tools, _

from odoo.exceptions import UserError
from ssl import SSLError

from cryptography.fernet import Fernet
from imaplib import IMAP4, IMAP4_SSL

from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime, timezone
import pytz

MAIL_TIMEOUT = 60

_logger = logging.getLogger(__name__)

IMAP4._create_socket = lambda self, timeout=MAIL_TIMEOUT: socket.create_connection(("docker.local" or None, 143), timeout)

class PortalFetchmail(models.Model):
    _name = 'portal.fetchmail'
    _description = 'Mail Portal Fetchmail Server'

    name = fields.Char('Name', required=True)
    active = fields.Boolean('Active', default=True)
    server = fields.Char('Server Name', required=True, default='docker.local', help="Hostname or IP of the mail server")
    port = fields.Integer(required=True, default=143)
    is_ssl = fields.Boolean('SSL/TLS', default=False, help="Use SSL/TLS for connection")

    attach = fields.Boolean('Keep Attachments', help="Whether attachments should be downloaded. "
                                                     "If not enabled, incoming emails will be stripped of any attachments before being processed", default=True)

    original = fields.Boolean('Keep Original', help="Whether a full original copy of each email should be kept for reference "
                                                    "and attached to each processed message. This will usually double the size of your message database.")
    date = fields.Datetime(string='Last Fetch Date', readonly=True)
    partner_id = fields.Many2one('res.partner', string='User', required=True, readonly=True, ondelete='cascade',
                            help="User who owns this email configuration")

    is_important = fields.Boolean('Important', default=False)

    username = fields.Char('Username', required=True)
    encrypted_password = fields.Char(
        required=True,
        copy=False,
        )


    def decrypt_password(self, encrypted_password):
        """
        Decrypt a password.
        """
        key = self._get_encryption_key()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_password.encode()).decode()


    def _get_encryption_key(self):
        """Retrieve the encryption key."""
        secret = self.env['ir.config_parameter'].sudo().get_param('database.secret')
        hashed_secret = hashlib.sha256(secret.encode()).digest()
        return base64.urlsafe_b64encode(hashed_secret)


    def connect(self):
        """Connect to the mail server."""
        self.ensure_one()   
        try:

            #TODO: REMOVE THIS 
            password = self.decrypt_password(self.encrypted_password) if self.username != 'user1@docker.local' else 'supersecret'
            _logger.info("[OLEK][portal.fetchmail][connect] PASSWORD: %s" % password)

            if self.is_ssl:
                mail_server = IMAP4_SSL('docker.local', int(self.port))
            else:
                mail_server = IMAP4('docker.local', int(self.port))
            # USERNAME AND PASSWORD 
            mail_server.login(self.username, password)
            return mail_server
        except Exception as e:
            _logger.error("Failed to connect to server: %s", e)
            raise


    def _prepare_mailbox_name(self, mailbox:str):
        """Prepare the mailbox name"""
        if mailbox != 'inbox':
            mailbox = mailbox.capitalize()
        return mailbox


    def _normalize_message_id(self, msg_id):
        """ Normalize a Message-ID to a more user-friendly format.

        :param msg_id: The full Message-ID string
        :type msg_id: str
        :return: A normalized version of the Message-ID
        """
        # Extracting the unique part of the Message-ID
        match = re.search(r'<(.+?)@', msg_id)
        if match:
            return match.group(1)
        return msg_id  # Return the original if no match found


    def confirm_login(self):
        for server in self:
            connection = None
            try:
                connection = server.connect()
                # server.write({'state': 'done'})
            except UnicodeError as e:
                raise UserError(_("Invalid server name!\n %s", tools.ustr(e)))
            except (gaierror, timeout, IMAP4.abort) as e:
                raise UserError(_("No response received. Check server information.\n %s", tools.ustr(e)))
            except (IMAP4.error) as err:
                raise UserError(_("Server replied with following exception:\n %s", tools.ustr(err)))
            except SSLError as e:
                raise UserError(_("An SSL exception occurred. Check SSL/TLS configuration on server port.\n %s", tools.ustr(e)))
            except (OSError, Exception) as err:
                _logger.info("Failed to connect to %s server %s.", server.name, exc_info=True)
                raise UserError(_("Connection test failed: %s", tools.ustr(err)))
            finally:
                try:
                    if connection:
                        connection.close()

                except Exception:
                    # ignored, just a consequence of the previous exception
                    pass
        return True

    def _check_imap_capabilities(self, mail_server):
        try:
            # mail_server = server.connect()
            typ, capabilities = mail_server.capability()
            if typ == 'OK':
                _logger.info("Server Capabilities: %s", capabilities)
            else:
                _logger.info("Failed to get server capabilities")
        except Exception as e:
            _logger.info("An error occurred: %s", e)

    #========================================================#
    # Methods for emails List 

    def fetch_mail_list(self, mailbox='inbox'):
        messages = []

        for server in self:
            try:
                mail_server = server.connect()
                mailbox = server._prepare_mailbox_name(mailbox)

                select_status, _ = mail_server.select(mailbox)
                if select_status != 'OK':
                    raise Exception(f"Failed to select mailbox: {mailbox}")

                typ, data = mail_server.uid('SEARCH', None, '(ALL)')

                if typ != 'OK':
                    raise Exception("No emails found.")

                uids = data[0].split()
                for e_uid in uids:
                    status, header_data = mail_server.uid('FETCH', e_uid, '(BODY.PEEK[HEADER])')

                    if status != 'OK':
                        raise Exception("Failed to fetch the email header.")

                    header = header_data[0][1]

                    if isinstance(header, str):
                        header = header.encode('utf-8')
                    email_message = message_from_bytes(header, policy=policy.SMTP)

                    # Parsing subject, date, message ID, references, etc.
                    email_info = self.parse_email_headers(email_message)

                    email_info['uid'] = int(e_uid.decode('utf-8'))
                    email_info['mailbox'] = mailbox

                    messages.append(email_info)

                mail_server.close()
                mail_server.logout()

            except Exception as e:
                _logger.error("[OLEK][fetch_mail_list] An error occurred: %s", e)
                raise

            self.env['portal.email.thread'].process_incoming_messages(messages)
            composed_threads = self.env['portal.email.thread'].get_threads()
            _logger.debug('[OLEK][portal.fetchmail][fetch_mail_list] composed_threads %s', composed_threads)

        _logger.debug('[OLEK][portal.fetchmail][fetch_mail_list] composed_threads %s', composed_threads)
        return composed_threads

    def parse_email_headers(self, email_message):
        email_info = {}
        email_info['subject'] = email_message['Subject']
        email_info['date'] = email_message['Date']
        email_info['message_id'] = email_message['Message-ID']
        email_info['references'] = email_message.get('References', '').split()
        email_info['sender'] = email_message['From']
        return email_info


    def compose_threads(self, messages):
        threads = []
        thread_lookup = {}

        for msg in messages:
            message_id = msg['message_id']
            references = msg['references']

            if references:
                thread_id = hashlib.md5(references[0].encode('utf-8')).hexdigest()
            else:
                thread_id = hashlib.md5(message_id.encode('utf-8')).hexdigest()

            msg_date = parsedate_to_datetime(msg['date'])
            if msg_date.tzinfo is None:
                msg_date = msg_date.replace(tzinfo=timezone.utc)

            if thread_id in thread_lookup:
                thread = thread_lookup[thread_id]
                thread['message_ids'].append(message_id)
                if msg_date > thread['date']:
                    thread['date'] = msg_date
            else:
                thread = {
                    'thread_id': thread_id,
                    'message_ids': [message_id],
                    'sender': msg['sender'],
                    'subject': msg['subject'],
                    'date': msg_date,
                }
                threads.append(thread)
                thread_lookup[thread_id] = thread

        # Sort the threads by date in descending order
        threads.sort(key=lambda x: x['date'], reverse=True)

        return threads

    # def compose_threads(self, messages):
    #     threads = {}

    #     for msg in messages:
    #         subject = msg['subject']
    #         message_id = msg['message_id']
    #         references = msg.get('references', [])

    #         thread_id = None
    #         for ref in references:
    #             if ref in threads:
    #                 thread_id = ref
    #                 break

    #         if thread_id is None:
    #             thread_id = message_id

    #         if thread_id not in threads:
    #             threads[thread_id] = []

    #         threads[thread_id].append(msg)

    #     return threads

    def store_threads_in_database(self, threads):
        # for thread_id, messages in threads.items():
            # Store the thread information in the Odoo database
            # Create or update the thread record
            # Associate the messages with the thread
            # You can use Odoo's ORM methods to interact with the database
            pass



    # def fetch_mail_list(self, mailbox='inbox'):
    #     """Fetch emails from the server and log them."""
    #     previews = []

    #     for server in self:
    #         # Connect to the mail server
    #         try:                
    #             mail_server = server.connect()
    #             mailbox = server._prepare_mailbox_name(mailbox)

    #             select_status, _ = mail_server.select(mailbox)
    #             if select_status != 'OK':
    #                 raise Exception(f"Failed to select mailbox: {mailbox}")

    #             typ, data = mail_server.uid('SEARCH',  None, '(ALL)')

    #             if typ != 'OK':
    #                 raise Exception("No emails found.")

    #             uids = data[0].split()
    #             for e_uid in uids:
    #                 status, email_data = mail_server.uid('FETCH', e_uid, '(RFC822)')

    #                 if status != 'OK':
    #                     raise Exception("Failed to fetch the email.")

    #                 message = email_data[0][1]

    #                 if isinstance(message, str):
    #                     message = message.encode('utf-8')
    #                 email_message = message_from_bytes(message, policy=policy.SMTP)

    #                 # Parsing subject date body etc.
    #                 email_preview = self.messages_previews_parse(email_message)

    #                 # UID RETRIEVING
    #                 _logger.debug('[OLEK][fetch_mail_list] e_id = %s', e_uid)

    #                 e_uid_int = int(e_uid.decode('utf-8'))

    #                 email_preview['uid'] = e_uid_int


    #                 previews.append(email_preview)
    #                 # Mark email as seen (optional based on requirement)
    #                 # mail_server.store(e_id, '+FLAGS', '\\Seen')

    #             # Logout/close the connection
    #             mail_server.close()
    #             mail_server.logout()
    
    #         except Exception as e:
    #             _logger.error("[OLEK][fetch_mail_list] An error occurred: %s", e)
    #             raise

    #     return previews
    

    @api.model
    def messages_previews_parse(self, message):
        """ Parse an email.message.Message to extract a preview.

        :param message: email to parse
        :type message: email.message.Message
        :rtype: dict
        :return: A dict containing a preview of the message:
                 { 'id': msg_id,
                   'subject': subject,
                   'email_from': from,
                   'preview': preview (first 50 characters of body) }
        """
        if not isinstance(message, EmailMessage):
            raise ValueError(_('Message should be a valid EmailMessage instance'))

        preview_dict = {}

        # # Extracting necessary details
        # preview_dict['id'] = message.get('Message-Id', '').strip()
        # _logger.info("[OLEK][messages_previews_parse] preview_dict['id']: %s", preview_dict['id'])
# ===================== OLD ==============================
        # # Extracting necessary details
        # full_msg_id = message.get('Message-Id', '').strip()
        # _logger.info("[OLEK][messages_previews_parse] full_msg_id: %s", full_msg_id)
        
        # # Normalize Message-ID
        # normalized_msg_id = self._normalize_message_id(full_msg_id)
        # preview_dict['msg_id'] = normalized_msg_id
        # _logger.info("[OLEK][messages_previews_parse] normalized_msg_id: %s", normalized_msg_id)
# =====================^^^^^^^ ====================================
        # #TODO : DELETE THIS
        # preview_dict['msg_id'] = 'TESTID'
        # # ^^^^^^^^^^^^^^^^^^===========

        preview_dict['subject'] = tools.decode_message_header(message, 'Subject')

        email_from = tools.decode_message_header(message, 'From')

        display_name, email_address = parseaddr(email_from)
        preview_dict['email_display_name'] = display_name.strip('"')  # Removes surrounding quotes
        preview_dict['email_address'] = email_address

        # preview_dict['email_from'] = tools.email_split_and_format(email_from)[0] if email_from else ''

        # Extracting a preview of the body (first 50 characters)
        body_preview = self._get_email_body_preview(message)
        preview_dict['preview'] = body_preview + '...' if body_preview else ''

        if message.get('Date'):
            try:
                date_hdr = tools.decode_message_header(message, 'Date')
                parsed_date = dateutil.parser.parse(date_hdr, fuzzy=True)
                if parsed_date.utcoffset() is None:
                    stored_date = parsed_date.replace(tzinfo=pytz.utc)
                else:
                    stored_date = parsed_date.astimezone(tz=pytz.utc)

                # Compare dates to determine format
                current_date = datetime.utcnow().replace(tzinfo=pytz.utc)
                if stored_date.date() == current_date.date():
                    # Message is from today, format as time only
                    preview_dict['date'] = stored_date.strftime('%H:%M')
                else:
                    # Message is from a previous day, format as abbreviated month and day
                    preview_dict['date'] = stored_date.strftime('%b %d')
            except Exception:
                _logger.info('Failed to parse Date header %r in incoming mail '
                             'with message-id %r, assuming current date/time.',
                             message.get('Date'))
                stored_date = datetime.now()
                preview_dict['date'] = stored_date.strftime('%H:%M')  # Default to time format for current date
        
        # _logger.debug('[OLEK][portal.fetchmail][messages_previews_parse] preview_dict %s', preview_dict)
        return preview_dict


    def _get_email_body_preview(self, message):
        """Extract the first 50 characters of the email body for preview.

        :param message: email to parse
        :type message: email.message.Message
        :rtype: str
        :return: First 50 characters of the email body
        """
        body = ""
        if message.is_multipart():
            for part in message.walk():
                # Focus on text parts only
                if part.get_content_maintype() == 'text':
                    charset = part.get_content_charset() or 'utf-8'
                    content = part.get_payload(decode=True).decode(charset, errors='replace')
                    # Break as soon as we get the first text part
                    body = content
                    break
        else:
            # Handle non-multipart emails
            charset = message.get_content_charset() or 'utf-8'
            body = message.get_payload(decode=True).decode(charset, errors='replace')

        # Return the first 50 characters
        return body[:100]



    #==================================================
    # Methods For Thread Fetching
    def fetch_mail_thread(self, mailbox, mail_uid, charset='UTF-8'):

        for server in self:
            try:
                mail_server = server.connect()
                mailbox = server._prepare_mailbox_name(mailbox)

                select_status, _ = mail_server.select()
                if not select_status:
                    raise Exception("Unable to select mailbox.")

                # Fetch the initial message, including important headers
                status, message_data = mail_server.uid('FETCH', mail_uid, '(RFC822 HEADER)')

                if status != 'OK':
                    raise Exception("Error fetching initial message.")

                message = message_from_bytes(message_data[0][1], policy=policy.SMTP)

                # Placeholder: Process initial message headers
                initial_message_id = message['Message-ID']  
                # ... (store any other relevant info)
                _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] initial_message_id %s', initial_message_id)
                thread_messages = [message]  # Start with the initial message
                _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] thread_messages %s', thread_messages)

                # Build the thread
                def build_thread(message):
                    message_id = message['Message-ID']
                    references = message.get_all('References', [])  # Includes In-Reply-To

                    if not message_id or not references:
                        return  # Cannot build the thread further

                    for ref_id in references:
                        status, data = mail_server.uid('SEARCH', charset, f'(HEADER Message-ID {ref_id})')
                        _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] ref_id %s', ref_id)
                        _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] data %s', data)
                        if status == 'OK' and data[0]:  # Found a matching message
                            ref_uid = data[0].split()[-1]  # Get the UID
                            status, message_data = mail_server.uid('FETCH', ref_uid, '(RFC822)')

                            if status == 'OK':
                                full_message = message_from_bytes(message_data[0][1], policy=policy.SMTP)
                                # ***Extract necessary headers***
                                message_id = full_message['Message-ID']  
                                references = full_message.get_all('References', [])  
                                thread_messages.append(full_message)  # Add the full message
                                build_thread(full_message)  # Recursive step

                build_thread(message)  # Start building the thread
                
                _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] thread_messages %s')

                return thread_messages

            except Exception as e:
                _logger.error("[OLEK][portal.fetchmail][fetch_mail_thread] An error occurred: %s", e)
                raise 


    # def fetch_mail_thread(self, mailbox, mail_uid, threading_algorithm='REFERENCES', charset='UTF-8'):
    # # def fetch_mail_thread(self, mailbox, mail_uid, threading_algorithm='ORDEREDSUBJECT', charset='UTF-8'):

    #     for server in self:
    #         try:
    #             mail_server = server.connect()
    #             mailbox = server._prepare_mailbox_name(mailbox)

    #             select_status, _ = mail_server.select()
    #             if not select_status:
    #                 raise Exception("Unable to select mailbox.")

    #             # Threading using UID
    #             status, thread_data = mail_server.uid('THREAD', threading_algorithm, charset, f'(HEADER Message-ID {mail_uid})')

    #             if status != 'OK':
    #                 raise Exception("Error during email threading.")

    #             _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] thread_data %s', thread_data)
    #             # Process thread_data
    #             thread_ids_str = thread_data[0].decode('utf-8')  # Decode to string
    #             # thread_ids = thread_ids_str.strip('()').split(')(')  # Remove parentheses and split

    #             thread_messages = []
    #             _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] thread_ids_str %s', thread_ids_str)
    #             # type of thread_data
    #             _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] thread_ids_str type %s', type(thread_ids_str))
    #             # Process thread_data
    #             for thread_uid in []: #thread_ids:
    #                 _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] thread_uid %s', thread_uid)

    #                 status, message_data = mail_server.uid('FETCH', thread_uid, '(RFC822)')
    #                 if status == 'OK':
    #                     _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] message_data %s', message_data)
    #                     # ... (Process message_data, extract Message-ID if needed) 
    #                     thread_messages.append(message_data) 
    #                 else:
    #                     _logger.warning("Failed to fetch message with UID: %s", thread_uid)

    #             return thread_messages

    #         except Exception as e:
    #             _logger.error("[OLEK][portal.fetchmail][fetch_mail_thread] An error occurred: %s", e)
    #             raise


    # ========================================= OLD =========================

    # def fetch_mail_thread(self, mailbox, mail_id, threading_algorithm='REFERENCES', charset='UTF-8'):
    #     for server in self:
    #         try:
    #             mailbox = server._prepare_mailbox_name(mailbox)

    #             mail_server = server.connect()

    #             select_status, _ = mail_server.select()
    #             if select_status:
    #                 _logger.info('[OLEK][portal.fetchmail][fetch_mail_thread] select_status %s', select_status)

    #             # if select_status != 'OK':
    #             #     raise Exception('Failed to select mailbox %s' % mailbox)

    #             status, email_ids = mail_server.search(None, '(ALL)')
    #             if status != 'OK':
    #                 raise Exception("No emails found.")

    #             _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] email_ids %s', email_ids)

    #             # server._check_imap_capabilities(mail_server)

    #             # mail_id = str(mail_id).encode('utf-8')
    #             # Convert the normalized ID back to its original format

                
    #             # full_mail_id = "<{}@docker.local>".format(mail_id)

    #             # _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] full_mail_id %s', full_mail_id)

                
    #             # # Search for the numeric ID associated with the full_mail_id
    #             # typ, data = mail_server.search(None, '(HEADER Message-ID "%s")' % full_mail_id)
    #             # if typ != 'OK' or not data[0]:
    #             #     _logger.error("Failed to find message with Message-ID %s", full_mail_id)
    #             #     return []

    #             # numeric_id = data[0].split()[0]  # Assuming the first result is the correct one
    #             # _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] Numeric ID %s', numeric_id)

    #             # # Fetch the headers of the specified email using its numeric ID
    #             # status, email_data = mail_server.fetch(numeric_id, '(RFC822.HEADER)')
    #             # if status == 'OK':
    #             #     headers = email_data[0][1].decode('utf-8')
    #             #     _logger.info('[OLEK][portal.fetchmail][fetch_mail_thread] Email Headers: %s', headers)
    #             # else:
    #             #     _logger.error('[OLEK][portal.fetchmail][fetch_mail_thread] Failed to fetch email headers')


    #             # # Fetching the thread containing the specific email
    #             # status, thread_data = mail_server.thread(threading_algorithm, charset, 'HEADER Message-ID "%s"' % mail_id)


    #                      # Search for messages in the mailbox to set the search context


    #             # # Now perform the threading on the searched messages
    #             # status, thread_data = mail_server.thread(threading_algorithm, charset, 'ALL')
                
    #             # result = mail_server.uid('thread', threading_algorithm, charset, 'ALL')
    #             # _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] result %s', result)

    #             # _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] Thread status %s', status)
    #             # _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] Thread data %s', thread_data)

    #             # if status != 'OK':
    #             #     raise Exception("Failed to fetch thread")

    #             # # Parsing thread data
    #             # thread_emails = self.parse_thread_data(thread_data)
    #             thread_messages = []

    #             # # Fetching details for each email in the thread
    #             # for email_id in thread_emails:    
    #             #     status, email_data = mail_server.fetch(email_id, '(RFC822)')
    #             #     if status == 'OK':
    #             #         msg_dict = server.message_process(email_data[0][1])
    #             #         thread_messages.append(msg_dict)

    #             # _logger.debug('[OLEK][portal.fetchmail][fetch_mail_thread] thread_messages %s', thread_messages)

    #             return thread_messages
    #         except Exception as e:
    #             _logger.error("[OLEK][portal.fetchmail][fetch_mail_thread] An error occurred: %s", e)
    #             raise

# ============================================================== OLD =============================#

    def parse_thread_data(self, thread_data):
        """
        Parses the thread data returned by the IMAP THREAD command
        and extracts individual message IDs.
        """
        # Example thread data format: '1 2 3 4 5'
        thread_emails = []
        for data in thread_data:
            if data is not None:
                thread_emails.extend(data.decode('utf-8').split())

        _logger.debug('[OLEK][portal.fetchmail][parse_thread_data] thread_emails %s', thread_emails)


        return thread_emails


    #======================================================#
    # Methods For Individual View

    @api.model
    def fetch_thread_messages(self, message_ids):
        messages = []
        for server in self:
            try:
                mail_server = server.connect()
                for msg_id in message_ids:
                    typ, msg_data = mail_server.uid('FETCH', msg_id, '(RFC822)')
                    if typ == 'OK':
                        email_message = message_from_string(msg_data[0][1], policy=email.policy.default)
                        # Parse and process the email message
                        messages.append(email_message)
                mail_server.close()
                mail_server.logout()
            except Exception as e:
                _logger.error("[OLEK][fetch_thread_messages] An error occurred: %s", e)
                raise
        return messages

    def fetch_mail_detail(self, mailbox, mail_id):
        for server in self:
            try:
                mailbox = server._prepare_mailbox_name(mailbox)

                mail_server = server.connect()
                mail_server.select(mailbox)


                mail_id = str(mail_id).encode('utf-8')

                _logger.debug('[OLEK][portal.fetchmail][fetch_single_mail] mail_id %s', mail_id)

                # mail_server.search(None, '(HEADER Message-ID "%s")' % mail_id)
                status, email_data = mail_server.fetch(mail_id, '(RFC822)')
                _logger.debug('[OLEK][portal.fetchmail][fetch_single_mail] status %s', status)
                _logger.debug('[OLEK][portal.fetchmail][fetch_single_mail] email_data %s', email_data)

                msg_dict = server.message_process(email_data[0][1])

                _logger.debug('[OLEK][portal.fetchmail][fetch_single_mail] msg_dict %s', msg_dict)

                return msg_dict
            except Exception as e:
                _logger.error("[OLEK][portal.fetchmail][fetch_single_mail]An error occurred: %s", e)
                raise

    @api.model
    def message_process(self, message, email_id=None, save_original=False,):
        """Log the email data."""
        _logger.debug('[OLEK][portal.fetchmail][message_process] message %s', message)
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        email_message = message_from_bytes(message, policy=policy.SMTP)

        msg_dict = self.message_parse(email_message, save_original=save_original)

        _logger.debug('[OLEK][portal.fetchmail][message_process] msg_dict %s', msg_dict)

        return msg_dict


    @api.model
    def message_parse(self, message, save_original=False):
        """ Parses an email.message.Message representing an RFC-2822 email
        and returns a generic dict holding the message details.

        :param message: email to parse
        :type message: email.message.Message
        :param bool save_original: whether the returned dict should include
            an ``original`` attachment containing the source of the message
        :rtype: dict
        :return: A dict with the following structure, where each field may not
            be present if missing in original message::

            { 'message_id': msg_id,
              'subject': subject,
              'email_from': from,
              'to': to + delivered-to,
              'cc': cc,
              'recipients': delivered-to + to + cc + resent-to + resent-cc,
              'partner_ids': partners found based on recipients emails,
              'body': unified_body,
              'references': references,
              'in_reply_to': in-reply-to,
              'is_bounce': True if it has been detected as a bounce email
              'parent_id': parent mail.message based on in_reply_to or references,
              'is_internal': answer to an internal message (note),
              'date': date,
              'attachments': [('file1', 'bytes'),
                              ('file2', 'bytes')}
            }
        """
        if not isinstance(message, EmailMessage):
            raise ValueError(_('Message should be a valid EmailMessage instance'))
        msg_dict = {'message_type': 'email'}

        message_id = message.get('Message-Id')
        if not message_id:
            # Very unusual situation, be we should be fault-tolerant here
            message_id = "<%s@localhost>" % time.time()
            _logger.debug('Parsing Message without message-id, generating a random one: %s', message_id)
        msg_dict['message_id'] = message_id.strip()

        if message.get('Subject'):
            msg_dict['subject'] = tools.decode_message_header(message, 'Subject')

        email_from = tools.decode_message_header(message, 'From', separator=',')
        email_cc = tools.decode_message_header(message, 'cc', separator=',')
        email_from_list = tools.email_split_and_format(email_from)
        email_cc_list = tools.email_split_and_format(email_cc)
        msg_dict['email_from'] = email_from_list[0] if email_from_list else email_from
        msg_dict['from'] = msg_dict['email_from']  # compatibility for message_new
        msg_dict['cc'] = ','.join(email_cc_list) if email_cc_list else email_cc
        # Delivered-To is a safe bet in most modern MTAs, but we have to fallback on To + Cc values
        # for all the odd MTAs out there, as there is no standard header for the envelope's `rcpt_to` value.
        msg_dict['recipients'] = ','.join(set(formatted_email
            for address in [
                tools.decode_message_header(message, 'Delivered-To', separator=','),
                tools.decode_message_header(message, 'To', separator=','),
                tools.decode_message_header(message, 'Cc', separator=','),
                tools.decode_message_header(message, 'Resent-To', separator=','),
                tools.decode_message_header(message, 'Resent-Cc', separator=',')
            ] if address
            for formatted_email in tools.email_split_and_format(address))
        )
        msg_dict['to'] = ','.join(set(formatted_email
            for address in [
                tools.decode_message_header(message, 'Delivered-To', separator=','),
                tools.decode_message_header(message, 'To', separator=',')
            ] if address
            for formatted_email in tools.email_split_and_format(address))
        )

        # lol all possible values with prefix [OLEK][portal.fetchmail]
        email_normalized = tools.email_normalize(msg_dict['email_from'])
        _logger.info('[OLEK][portal.fetchmail][message_parse] email_normalized: %s', email_normalized)


        

        # partner_ids = [x.id for x in self._mail_find_partner_from_emails(tools.email_split(msg_dict['recipients']), records=self) if x]
        # msg_dict['partner_ids'] = partner_ids
        # compute references to find if email_message is a reply to an existing thread
        msg_dict['references'] = tools.decode_message_header(message, 'References')
        msg_dict['in_reply_to'] = tools.decode_message_header(message, 'In-Reply-To').strip()

        if message.get('Date'):
            try:
                date_hdr = tools.decode_message_header(message, 'Date')
                parsed_date = dateutil.parser.parse(date_hdr, fuzzy=True)
                if parsed_date.utcoffset() is None:
                    # naive datetime, so we arbitrarily decide to make it
                    # UTC, there's no better choice. Should not happen,
                    # as RFC2822 requires timezone offset in Date headers.
                    stored_date = parsed_date.replace(tzinfo=pytz.utc)
                else:
                    stored_date = parsed_date.astimezone(tz=pytz.utc)
            except Exception:
                _logger.info('Failed to parse Date header %r in incoming mail '
                             'with message-id %r, assuming current date/time.',
                             message.get('Date'), message_id)
                stored_date = datetime.datetime.now()
            msg_dict['date'] = stored_date.strftime(tools.DEFAULT_SERVER_DATETIME_FORMAT)

        # msg_dict.update(self._message_parse_extract_from_parent(self._get_parent_message(msg_dict)))
        # msg_dict.update(self._message_parse_extract_bounce(message, msg_dict))
        msg_dict.update(self._message_parse_extract_payload(message, msg_dict, save_original=save_original))
        return msg_dict


    def _message_parse_extract_payload(self, message, preview_dict, save_original=False):
        """Extract body as HTML and attachments from the mail message

        :param string message: an email.message instance
        """
        attachments = []
        body = ''
        if save_original:
            attachments.append(self._Attachment('original_email.eml', message.as_string(), {}))

        # Be careful, content-type may contain tricky content like in the
        # following example so test the MIME type with startswith()
        #
        # Content-Type: multipart/related;
        #   boundary="_004_3f1e4da175f349248b8d43cdeb9866f1AMSPR06MB343eurprd06pro_";
        #   type="text/html"
        if message.get_content_maintype() == 'text':
            encoding = message.get_content_charset()
            body = message.get_content()
            body = tools.ustr(body, encoding, errors='replace')
            if message.get_content_type() == 'text/plain':
                # text/plain -> <pre/>
                body = tools.append_content_to_html('', body, preserve=True)
            elif message.get_content_type() == 'text/html':
                # we only strip_classes here everything else will be done in by html field of mail.message
                body = tools.html_sanitize(body, sanitize_tags=False, strip_classes=True)
        else:
            alternative = False
            mixed = False
            html = ''
            for part in message.walk():
                if preview_dict.get('is_bounce') and body:
                    # bounce email, keep only the first body and ignore
                    # the parent email that might be added at the end
                    # (e.g. for outlook / yahoo bounce email)
                    break
                if part.get_content_type() == 'binary/octet-stream':
                    _logger.warning("Message containing an unexpected Content-Type 'binary/octet-stream', assuming 'application/octet-stream'")
                    part.replace_header('Content-Type', 'application/octet-stream')
                if part.get_content_type() == 'multipart/alternative':
                    alternative = True
                if part.get_content_type() == 'multipart/mixed':
                    mixed = True
                if part.get_content_maintype() == 'multipart':
                    continue  # skip container

                filename = part.get_filename()  # I may not properly handle all charsets
                if part.get_content_type() == 'text/xml' and not part.get_param('charset'):
                    # for text/xml with omitted charset, the charset is assumed to be ASCII by the `email` module
                    # although the payload might be in UTF8
                    part.set_charset('utf-8')
                encoding = part.get_content_charset()  # None if attachment

                content = part.get_content()
                info = {'encoding': encoding}
                # 0) Inline Attachments -> attachments, with a third part in the tuple to match cid / attachment
                if filename and part.get('content-id'):
                    info['cid'] = part.get('content-id').strip('><')
                    attachments.append(self._Attachment(filename, content, info))
                    continue
                # 1) Explicit Attachments -> attachments
                if filename or part.get('content-disposition', '').strip().startswith('attachment'):
                    attachments.append(self._Attachment(filename or 'attachment', content, info))
                    continue
                # 2) text/plain -> <pre/>
                if part.get_content_type() == 'text/plain' and (not alternative or not body):
                    body = tools.append_content_to_html(body, tools.ustr(content,
                                                                         encoding, errors='replace'), preserve=True)
                # 3) text/html -> raw
                elif part.get_content_type() == 'text/html':
                    # mutlipart/alternative have one text and a html part, keep only the second
                    # mixed allows several html parts, append html content
                    append_content = not alternative or (html and mixed)
                    html = tools.ustr(content, encoding, errors='replace')
                    if not append_content:
                        body = html
                    else:
                        body = tools.append_content_to_html(body, html, plaintext=False)
                    # we only strip_classes here everything else will be done in by html field of mail.message
                    body = tools.html_sanitize(body, sanitize_tags=False, strip_classes=True)
                # 4) Anything else -> attachment
                else:
                    attachments.append(self._Attachment(filename or 'attachment', content, info))

        return self._message_parse_extract_payload_postprocess(message, {'body': body, 'attachments': attachments})

    def _message_parse_extract_payload_postprocess(self, message, payload_dict):
        """ Perform some cleaning / postprocess in the body and attachments
        extracted from the email. Note that this processing is specific to the
        mail module, and should not contain security or generic html cleaning.
        Indeed those aspects should be covered by the html_sanitize method
        located in tools.

        :param string message: an email.message instance
        """
        body, attachments = payload_dict['body'], payload_dict['attachments']
        if not body.strip():
            return {'body': body, 'attachments': attachments}
        try:
            root = lxml.html.fromstring(body)
        except ValueError:
            # In case the email client sent XHTML, fromstring will fail because 'Unicode strings
            # with encoding declaration are not supported'.
            root = lxml.html.fromstring(body.encode('utf-8'))

        postprocessed = False
        to_remove = []
        for node in root.iter():
            if 'o_mail_notification' in (node.get('class') or '') or 'o_mail_notification' in (node.get('summary') or ''):
                postprocessed = True
                if node.getparent() is not None:
                    to_remove.append(node)
            if node.tag == 'img' and node.get('src', '').startswith('cid:'):
                cid = node.get('src').split(':', 1)[1]
                related_attachment = [attach for attach in attachments if attach[2] and attach[2].get('cid') == cid]
                if related_attachment:
                    node.set('data-filename', related_attachment[0][0])
                    postprocessed = True

        for node in to_remove:
            node.getparent().remove(node)
        if postprocessed:
            body = Markup(etree.tostring(root, pretty_print=False, encoding='unicode'))
        return {'body': body, 'attachments': attachments}