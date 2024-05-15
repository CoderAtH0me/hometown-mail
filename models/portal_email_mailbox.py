from odoo import _, fields, models


class PortalMailbox(models.Model):
    _name = 'portal.email.mailbox'
    _description = 'Email Mailbox'

    name = fields.Char(string='Mailbox Name', required=True)
    mailbox_type = fields.Selection([
        ('inbox', 'Inbox'),
        ('sent', 'Sent'),
        ('drafts', 'Drafts'),
        ('spam', 'Spam'),
        ('trash', 'Trash'),
    ], required=True, string='Mailbox Type')