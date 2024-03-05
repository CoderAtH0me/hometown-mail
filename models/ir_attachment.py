# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

# import contextlib

from odoo import _, api, models, SUPERUSER_ID
# from odoo.exceptions import AccessError, MissingError, UserError
# from odoo.http import request
# from odoo.tools import consteq


class IrAttachment(models.Model):

    _inherit = 'ir.attachment'