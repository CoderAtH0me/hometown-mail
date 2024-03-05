# -*- coding: utf-8 -*-

from odoo import models, fields, api
import subprocess
import string
import random
import base64
import hashlib
from cryptography.fernet import Fernet

import logging

_logger = logging.getLogger(__name__)


class Partner(models.Model):
    _name = "res.partner"
    _inherit = 'res.partner'

    imap_server = fields.Char(string="IMAP Server", default="docker.local", required=True)
    imap_port = fields.Char(string="IMAP Port", default=143, required=True)
    imap_encrypted_password = fields.Char(
        compute="_compute_imap_password",
        required=True,
        store=True)
    imap_folder = fields.Char(string="IMAP Folder")
    imap_ssl = fields.Boolean(string="IMAP SSL", default=False)
    imap_delete = fields.Boolean(string="IMAP Delete")
    imap_keep = fields.Boolean(string="IMAP Keep")
    imap_keep_days = fields.Integer(string="IMAP Keep Days")
    imap_keep_count = fields.Integer(string="IMAP Keep Count")
    imap_keep_size = fields.Integer(string="IMAP Keep Size")
    imap_keep_size_unit = fields.Selection([
        ('MB', 'MB'),
        ('GB', 'GB')
        ], string="IMAP Keep Size Unit")
    
    fetchmail_server = fields.One2many('portal.fetchmail', 'partner_id', string="Fetchmail Server")

    @api.depends('email', 'imap_server', 'imap_port', 'imap_ssl')
    def _compute_imap_password(self):
        """Compute the encrypted password."""
        _logger.info("[OLEK][res.partner][_compute_imap_password] FIRST TRIGGER self: %s", self)
        for partner in self:
            _logger.info("[OLEK][res.partner][_compute_imap_password] partner: %s", partner)

            password = partner._generate_strong_password()
            _logger.debug("[OLEK][res.partner][_compute_imap_password] password: %s", password)
            encrypted_password = partner._encrypt_password(password)
            partner.imap_encrypted_password = encrypted_password

            if not partner.fetchmail_server:
                self.env['portal.fetchmail'].create({
                    'name': f'Fetchmail for {partner.name}',
                    'server': partner.imap_server,
                    'port': partner.imap_port,
                    'is_ssl': partner.imap_ssl,
                    'username': partner.email,
                    'encrypted_password': encrypted_password,
                    'partner_id': partner.id,
                    # ... other necessary fields ...
                })

            _logger.info("[OLEK][res.partner][_compute_imap_password] EMAIL %s AND PASSWORD: %s", partner.email, password)
            partner._create_mailbox(partner.email, password)


    def _generate_strong_password(self, length=12):
        """Generate a strong random password."""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for i in range(length))

    def _encrypt_password(self, password):
        """Encrypt a password."""
        key = self._get_encryption_key()
        fernet = Fernet(key)
        return fernet.encrypt(password.encode()).decode()

    def _get_encryption_key(self):
        """Retrieve the encryption key."""
        secret = self.env['ir.config_parameter'].sudo().get_param('database.secret')
        hashed_secret = hashlib.sha256(secret.encode()).digest()
        return base64.urlsafe_b64encode(hashed_secret)


    def _create_mailbox(self, email, password):
        """Create a mailbox on docker-mailserver."""
        _logger.info("[OLEK][res.partner][_create_mailbox] EMAIL %s AND PASSWORD: %s", email, password)

        try:
            command = (
                "docker run --rm "
                f"--env MAIL_USER={email} "
                f"--env MAIL_PASS={password} "
                "mailserver/docker-mailserver "
                "/bin/sh -c "
                f"\'echo \"$MAIL_USER|$(doveadm pw -s SHA512-CRYPT -u $MAIL_USER -p $MAIL_PASS)\"\' >> /opt/odoo/docker/mailserver/config/postfix-accounts.cf"
            )

            _logger.info(f"Command: {command}")

            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _logger.info(f"Command stdout: {result.stdout}")
            _logger.info(f"Command stderr: {result.stderr}")
        except subprocess.CalledProcessError as e:
            _logger.error(f"Command failed with stdout: {e.stdout}")
            _logger.error(f"Command failed with stderr: {e.stderr}")
            raise Exception(f"Error creating mailbox: {e}")
