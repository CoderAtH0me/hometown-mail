# Part of Odoo. See LICENSE file for full copyright and licensing details.

from collections import defaultdict

from odoo import _, api, Command, fields, models, modules, tools
from odoo.tools import email_normalize


class Users(models.Model):
    """ Update of res.users class
        - add a preference about sending emails about notifications
        - make a new user follow itself
        - add a welcome message
        - add suggestion preference
    """
    _name = 'res.users'
    _inherit = ['res.users']
