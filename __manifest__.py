# -*- coding: utf-8 -*-

{
    'name': 'Portal Email Management',  # Name of your module
    'version': '1.0',  # Version of the module
    'summary': 'Manage Email Accounts in Portal',  # Short summary
    'sequence': 10,  # Determines the order of modules in the module list
    'description': """
Manage Your Email Accounts
==========================

This module provides email management features within the Odoo portal,
allowing users to view and manage their email accounts.
    """,  # Detailed description of your module
    'category': 'Extra Tools',  # Module category, helps in filtering modules in the apps list
    'website': 'https://www.yourcompanywebsite.com',  # Website for the module or your company
    'depends': [
        'portal', 
        'mail', 
        'base_setup', 
        'web', 
        'http_routing',
        'auth_signup',
        'website_partner',
        'web_tour'],  # List of dependencies, include all modules your module depends on
    'data': [
        # List of data files which should be loaded when installing/updating the module
        'views/portal_email_templates.xml',
        'views/portal_email_details.xml',
        'security/ir.model.access.csv',
        'data/portal_mailbox_data.xml',
    ],
    'assets': {
        'web.assets_frontend': [
            'mail_portal/static/src/js/portal_dashboard.js',
        ],
    },
    'demo': [
        # List of demo data files, useful for demonstration and testing purposes
    ],
    'installable': True,  # Indicates if the module can be installed
    'application': True,  # True if your module is an application, False if it's merely a library/module
    'auto_install': False,  # True if the module should be automatically installed when all dependencies are
    'license': 'LGPL-3',  # Software license of your module
}