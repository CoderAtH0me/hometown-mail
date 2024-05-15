import ast
import base64
import datetime
import dateutil
import email
import email.policy
import hashlib
import hmac
import json
import lxml
import logging
import pytz
import re
import time
import threading

from email.utils import parsedate_to_datetime, parseaddr
from datetime import timezone

from xmlrpc import client as xmlrpclib
from email.message import EmailMessage
from email import message_from_string, message_from_bytes, policy

from odoo import _, api, exceptions, fields, models, tools, registry, SUPERUSER_ID, Command

_logger = logging.getLogger(__name__)

class MailThread(models.Model):
    _name = 'portal.email.thread'
    _description = 'Portal Email Thread'

    thread_id = fields.Char(string='Thread ID', required=True, index=True)
    message_ids = fields.Char(string='Message IDs', required=True)
    sender = fields.Char(string='Sender', required=True)
    subject = fields.Char(string='Subject', required=True)
    date = fields.Datetime(string='Date', required=True)
    references = fields.Char(string='References')
    partner_id = fields.Many2one('res.partner', string='User', required=True, readonly=True, ondelete='cascade',
                                 help="User who owns this thread")
    mailbox_ids = fields.Many2many('portal.email.mailbox', string='Mailboxes')

    @api.model
    def message_parse(self, message, save_original=False):
        if not isinstance(message, EmailMessage):
            if isinstance(message, bytes):
                message = message_from_bytes(message, policy=policy.SMTP)
            else:
                raise ValueError(_('Message should be a valid bytes or EmailMessage instance'))

        msg_dict = {}
        message_id = message.get('Message-Id')
        if not message_id:
            message_id = "<%s@localhost>" % time.time()
            _logger.debug('Parsing Message without message-id, generating a random one: %s', message_id)
        msg_dict['message_id'] = message_id.strip()

        if message.get('Subject'):
            msg_dict['subject'] = tools.decode_message_header(message, 'Subject')

        email_from = tools.decode_message_header(message, 'From')
        msg_dict['email_from'] = tools.email_split_and_format(email_from)[0]
        msg_dict['from'] = msg_dict['email_from']

        msg_dict['to'] = tools.decode_message_header(message, 'To')
        msg_dict['cc'] = tools.decode_message_header(message, 'Cc')

        msg_dict['recipients'] = ','.join(set(formatted_email
            for address in [
                tools.decode_message_header(message, 'Delivered-To'),
                tools.decode_message_header(message, 'To'),
                tools.decode_message_header(message, 'Cc'),
                tools.decode_message_header(message, 'Resent-To'),
                tools.decode_message_header(message, 'Resent-Cc')
            ] if address
            for formatted_email in tools.email_split_and_format(address))
        )

        if message.get('Date'):
            msg_dict['date'] = message.get('Date')

        msg_dict['references'] = message.get('References', '').split()

        return msg_dict

    @api.model
    def create_update_thread(self, msg_dict):
        message_id = msg_dict['message_id']
        references = msg_dict.get('references', [])

        _logger.debug('[OLEK][portal_email_thread][create_update_thread] msg_dict %s', msg_dict)

        if references:
            thread_id = hashlib.md5(references[0].encode('utf-8')).hexdigest()
        else:
            thread_id = hashlib.md5(message_id.encode('utf-8')).hexdigest()

        msg_date = parsedate_to_datetime(msg_dict['date'])
        if msg_date.tzinfo is None:
            msg_date = msg_date.replace(tzinfo=timezone.utc)

        # Convert aware datetime to naive datetime
        msg_date_naive = msg_date.astimezone(timezone.utc).replace(tzinfo=None)

        thread = self.search([('thread_id', '=', thread_id)])

        # Extract the actual email address using parseaddr
        recipient_email = parseaddr(msg_dict['recipients'].split(',')[0])[1]
        partner = self.env['res.partner'].sudo().search([('email', '=', recipient_email)], limit=1)
        if not partner:
            _logger.warning("No matching partner found for recipient email: %s", recipient_email)
            return

        # Determine applicable mailboxes
        mailbox_inbox = self.env['portal.email.mailbox'].search([('mailbox_type', '=', 'inbox')], limit=1)
        mailbox_sent = self.env['portal.email.mailbox'].search([('mailbox_type', '=', 'sent')], limit=1)

        _logger.debug('[OLEK][portal_email_thread][create_update_thread] mailbox_inbox %s', mailbox_inbox)

        mailbox_ids = []
        if msg_dict['from'] == partner.email:
            mailbox_ids.append(mailbox_sent.id)
        if recipient_email == partner.email:
            mailbox_ids.append(mailbox_inbox.id)
            
        _logger.debug('[OLEK][portal_email_thread][create_update_thread] msg_date_naive %s', msg_date_naive)

        if thread:
            _logger.debug('[OLEK][portal_email_thread][create_update_thread] Updating existing thread %s', thread_id)

            thread.write({
                'message_ids': thread.message_ids + ',' + message_id,
                'date': msg_date_naive if msg_date_naive > thread.date else thread.date,
                'mailbox_ids': [(4, mailbox_id) for mailbox_id in mailbox_ids]
            })
        else:
            _logger.debug('[OLEK][portal_email_thread][create_update_thread] Creating new thread %s', thread_id)

            self.create({
                'thread_id': thread_id,
                'message_ids': message_id,
                'sender': msg_dict['from'],
                'subject': msg_dict['subject'],
                'date': msg_date_naive,
                'references': ','.join(references),
                'partner_id': partner.id,
                'mailbox_ids': [(6, 0, mailbox_ids)]
            })

    @api.model
    def process_incoming_messages(self, model, message, custom_values=None,
                                  save_original=False, strip_attachments=False,
                                  thread_id=None):
        """
        Catches an incoming email that was piped through the sieve script on the mail server side.
        
        Handles a single message.
        """

        if isinstance(message, xmlrpclib.Binary):
            message = bytes(message.data)
        if isinstance(message, str):
            message = message.encode('utf-8')
        message = email.message_from_bytes(message, policy=email.policy.SMTP)

        _logger.info('[OLEK][portal_email_thread][message_process] Incoming mail message_from_bytes %s', message)

        msg_dict = self.message_parse(message, save_original=save_original)
        _logger.info('[OLEK][portal_email_thread][message_process] Incoming mail message_parse %s', msg_dict)

        self.create_update_thread(msg_dict)

        return True

    @api.model
    def get_threads(self, partner_id, mailbox_type=None):
        domain = [('partner_id', '=', partner_id)]
        if mailbox_type:
            domain.append(('mailbox_ids.mailbox_type', '=', mailbox_type))

        threads = self.search(domain, order='date desc')
        return [{
            'thread_id': thread.thread_id,
            'message_ids': thread.message_ids.split(','),
            'sender': thread.sender,
            'subject': thread.subject,
            'date': thread.date,
        } for thread in threads]
        
    # # _mail_flat_thread = True  # flatten the discussion history
    # # _mail_post_access = 'write'  # access required on the document to post on it
    # # _primary_email = 'email'  # Must be set for the models that can be created by alias
    # # _Attachment = namedtuple('Attachment', ('fname', 'content', 'info'))

    # @api.model
    # def message_parse(self, message, save_original=False):
    #     """ Parses an email.message.Message representing an RFC-2822 email
    #     and returns a generic dict holding the message details.

    #     :param message: email to parse
    #     :type message: email.message.Message
    #     :param bool save_original: whether the returned dict should include
    #         an ``original`` attachment containing the source of the message
    #     :rtype: dict
    #     :return: A dict with the following structure, where each field may not
    #         be present if missing in original message::

    #         { 'message_id': msg_id,
    #           'subject': subject,
    #           'email_from': from,
    #           'to': to + delivered-to,
    #           'cc': cc,
    #           'recipients': delivered-to + to + cc + resent-to + resent-cc,
    #           'partner_ids': partners found based on recipients emails,
    #           'body': unified_body,
    #           'references': references,
    #           'in_reply_to': in-reply-to,
    #           'is_bounce': True if it has been detected as a bounce email
    #           'parent_id': parent mail.message based on in_reply_to or references,
    #           'is_internal': answer to an internal message (note),
    #           'date': date,
    #           'attachments': [('file1', 'bytes'),
    #                           ('file2', 'bytes')}
    #         }
    #     """
    #     if not isinstance(message, EmailMessage):
    #         raise ValueError(_('Message should be a valid EmailMessage instance'))
    #     msg_dict = {'message_type': 'email'}

    #     message_id = message.get('Message-Id')
    #     if not message_id:
    #         # Very unusual situation, be we should be fault-tolerant here
    #         message_id = "<%s@localhost>" % time.time()
    #         _logger.debug('Parsing Message without message-id, generating a random one: %s', message_id)
    #     msg_dict['message_id'] = message_id.strip()

    #     if message.get('Subject'):
    #         msg_dict['subject'] = tools.decode_message_header(message, 'Subject')

    #     email_from = tools.decode_message_header(message, 'From', separator=',')
    #     email_cc = tools.decode_message_header(message, 'cc', separator=',')
    #     email_from_list = tools.email_split_and_format(email_from)
    #     email_cc_list = tools.email_split_and_format(email_cc)
    #     msg_dict['email_from'] = email_from_list[0] if email_from_list else email_from
    #     msg_dict['from'] = msg_dict['email_from']  # compatibility for message_new
    #     msg_dict['cc'] = ','.join(email_cc_list) if email_cc_list else email_cc
    #     # Delivered-To is a safe bet in most modern MTAs, but we have to fallback on To + Cc values
    #     # for all the odd MTAs out there, as there is no standard header for the envelope's `rcpt_to` value.
    #     msg_dict['recipients'] = ','.join(set(formatted_email
    #         for address in [
    #             tools.decode_message_header(message, 'Delivered-To', separator=','),
    #             tools.decode_message_header(message, 'To', separator=','),
    #             tools.decode_message_header(message, 'Cc', separator=','),
    #             tools.decode_message_header(message, 'Resent-To', separator=','),
    #             tools.decode_message_header(message, 'Resent-Cc', separator=',')
    #         ] if address
    #         for formatted_email in tools.email_split_and_format(address))
    #     )
    #     msg_dict['to'] = ','.join(set(formatted_email
    #         for address in [
    #             tools.decode_message_header(message, 'Delivered-To', separator=','),
    #             tools.decode_message_header(message, 'To', separator=',')
    #         ] if address
    #         for formatted_email in tools.email_split_and_format(address))
    #     )

    #     # lol all possible values with prefix [OLEK][portal_email_thread]
    #     _logger.info('[OLEK][portal_email_thread][message_parse] msg_dict: %s', msg_dict)
    #     _logger.info('[OLEK][portal_email_thread][message_parse] email_from_list: %s', email_from_list)
        

    #     # partner_ids = [x.id for x in self._mail_find_partner_from_emails(tools.email_split(msg_dict['recipients']), records=self) if x]
    #     # msg_dict['partner_ids'] = partner_ids
    #     # # compute references to find if email_message is a reply to an existing thread
    #     # msg_dict['references'] = tools.decode_message_header(message, 'References')
    #     # msg_dict['in_reply_to'] = tools.decode_message_header(message, 'In-Reply-To').strip()

    #     # if message.get('Date'):
    #     #     try:
    #     #         date_hdr = tools.decode_message_header(message, 'Date')
    #     #         parsed_date = dateutil.parser.parse(date_hdr, fuzzy=True)
    #     #         if parsed_date.utcoffset() is None:
    #     #             # naive datetime, so we arbitrarily decide to make it
    #     #             # UTC, there's no better choice. Should not happen,
    #     #             # as RFC2822 requires timezone offset in Date headers.
    #     #             stored_date = parsed_date.replace(tzinfo=pytz.utc)
    #     #         else:
    #     #             stored_date = parsed_date.astimezone(tz=pytz.utc)
    #     #     except Exception:
    #     #         _logger.info('Failed to parse Date header %r in incoming mail '
    #     #                      'with message-id %r, assuming current date/time.',
    #     #                      message.get('Date'), message_id)
    #     #         stored_date = datetime.datetime.now()
    #     #     msg_dict['date'] = stored_date.strftime(tools.DEFAULT_SERVER_DATETIME_FORMAT)

    #     # msg_dict.update(self._message_parse_extract_from_parent(self._get_parent_message(msg_dict)))
    #     # msg_dict.update(self._message_parse_extract_bounce(message, msg_dict))
    #     # msg_dict.update(self._message_parse_extract_payload(message, msg_dict, save_original=save_original))
    #     return msg_dict

    # @api.model
    # def message_process(self, model, message, custom_values=None,
    #                     save_original=False, strip_attachments=False,
    #                     thread_id=None):
    #     """ Process an incoming RFC2822 email message, relying on
    #         ``mail.message.parse()`` for the parsing operation,
    #         and ``message_route()`` to figure out the target model.

    #         Once the target model is known, its ``message_new`` method
    #         is called with the new message (if the thread record did not exist)
    #         or its ``message_update`` method (if it did).

    #        :param string model: the fallback model to use if the message
    #            does not match any of the currently configured mail aliases
    #            (may be None if a matching alias is supposed to be present)
    #        :param message: source of the RFC2822 message
    #        :type message: string or xmlrpclib.Binary
    #        :type dict custom_values: optional dictionary of field values
    #             to pass to ``message_new`` if a new record needs to be created.
    #             Ignored if the thread record already exists, and also if a
    #             matching mail.alias was found (aliases define their own defaults)
    #        :param bool save_original: whether to keep a copy of the original
    #             email source attached to the message after it is imported.
    #        :param bool strip_attachments: whether to strip all attachments
    #             before processing the message, in order to save some space.
    #        :param int thread_id: optional ID of the record/thread from ``model``
    #            to which this mail should be attached. When provided, this
    #            overrides the automatic detection based on the message
    #            headers.
    #     """
    #     # extract message bytes - we are forced to pass the message as binary because
    #     # we don't know its encoding until we parse its headers and hence can't
    #     # convert it to utf-8 for transport between the mailgate script and here.
    #     if isinstance(message, xmlrpclib.Binary):
    #         message = bytes(message.data)
    #     if isinstance(message, str):
    #         message = message.encode('utf-8')
    #     message = email.message_from_bytes(message, policy=email.policy.SMTP)

    #     _logger.info('[OLEK][portal_email_thread][message_process] Incoming mail message_from_bytes %s', message)
        
    #     # parse the message, verify we are not in a loop by checking message_id is not duplicated
    #     msg_dict = self.message_parse(message, save_original=save_original)
    #     _logger.info('[OLEK][portal_email_thread][message_process] Incoming mail message_parse %s', msg_dict)

    #     # if strip_attachments:
    #     #     msg_dict.pop('attachments', None)

    #     # existing_msg_ids = self.env['mail.message'].search([('message_id', '=', msg_dict['message_id'])], limit=1)
    #     # if existing_msg_ids:
    #     #     _logger.info('Ignored mail from %s to %s with Message-Id %s: found duplicated Message-Id during processing',
    #     #                  msg_dict.get('email_from'), msg_dict.get('to'), msg_dict.get('message_id'))
    #     #     return False

    #     # if self._detect_loop_headers(msg_dict):
    #     #     return

    #     # # find possible routes for the message
    #     # routes = self.message_route(message, msg_dict, model, thread_id, custom_values)
    #     # if self._detect_loop_sender(message, msg_dict, routes):
    #     #     return

    #     # thread_id = self._message_route_process(message, msg_dict, routes)
    #     # return thread_id
    #     return True
