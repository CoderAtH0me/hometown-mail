import logging

from odoo import http
from odoo.http import request
from odoo.addons.portal.controllers.portal import CustomerPortal, pager as portal_pager

_logger = logging.getLogger(__name__)

class EmailCustomerPortal(CustomerPortal):

    def _prepare_home_portal_values(self, counters):
        values = super()._prepare_home_portal_values(counters)
        if 'emails_count' in counters:
            values['emails_count'] = request.env['portal.email.message'].search_count([]) \
                if request.env['portal.email.message'].check_access_rights('read', raise_exception=False) else 0
        return values


    # @http.route(['/my/emails', '/my/emails/page/<int:page>'], type='http', auth="user", website=True)
    # def portal_my_emails(self, page=1, **kw):
    #     values = self._prepare_portal_layout_values()

    #     # Hardcoded values for testing
    #     emails = [{
    #         'id': 1,
    #         'subject': 'Test Email 1',
    #         'date': '2023-01-01 10:00:00',
    #     }, {
    #         'id': 2,
    #         'subject': 'Test Email 2',
    #         'date': '2023-01-02 11:00:00',
    #     }]

    #     values.update({
    #         'emails': emails,
    #         'page_name': 'email',
    #         'default_url': '/my/emails',
    #         'pager': {},  # Empty pager for testing
    #     })
    #     return request.render("mail_portal.portal_my_emails", values)

    # @http.route(['/my/emails', '/my/emails/page/<int:page>'], type='http', auth="user", website=True)
    # def portal_my_emails(self, page=1, **kw):
    #     values = self._prepare_portal_layout_values()

    #     # Fetch stored emails from the database instead of using hardcoded values
    #     Email = request.env['portal.email.message']
    #     domain = []  # Add your domain filters as needed
    #     emails = Email.search(domain, order='date desc')  # Adjust the search as needed

    #     _logger.debug("[OLEK][MAIN]:portal_my_emails emails %s", emails)
    #     # Update values with real emails
    #     values.update({
    #         'emails': emails,
    #         'page_name': 'email',
    #         'default_url': '/my/emails',
    #         # Use the pager for real navigation through pages
    #         'pager': portal_pager(
    #             url="/my/emails",
    #             total=len(emails),
    #             page=page,
    #             step=self._items_per_page
    #         ),
    #     })

    #     return request.render("mail_portal.portal_my_emails", values)

    #=========================== INBOX ====================================
    # @http.route(['/my/inbox', '/my/inbox/page/<int:page>'], type='http', auth='user', website=True)
    # def portal_inbox(self, page=1, **kw):
    #     values = self._prepare_portal_layout_values()

    #     current_user_partner_id = request.env.user.partner_id.id
    #     record = request.env['portal.fetchmail'].sudo().search([('partner_id', '=', current_user_partner_id)], limit=1)
    #     email_previews = record.fetch_mail_list()
    #     # Use the pager for real navigation through pages
    #     pager = portal_pager(
    #         url="/my/inbox",
    #         total=10,
    #         page=page,
    #         step=self._items_per_page
    #     )
    #     # Add the email previews to the values passed to the view
    #     values.update({
    #         'emails': email_previews,
    #         'page_name': 'email',
    #         'default_url': '/my/inbox',
    #         'pager': pager,
    #     })

    #     return request.render("mail_portal.portal_my_emails", values)

    # @http.route(['/my/<string:mailbox>', '/my/<string:mailbox>/page/<int:page>'], type='http', auth='user', website=True)
    # def portal_mailbox(self, mailbox='inbox', page=1, **kw):
    #     values = self._prepare_portal_layout_values()

    #     current_user_partner_id = request.env.user.partner_id.id
    #     record = request.env['portal.fetchmail'].sudo().search([('partner_id', '=', current_user_partner_id)], limit=1)

    #     if record:
    #         email_previews = record.fetch_mail_list(mailbox=mailbox)

    #         # Use the pager for real navigation through pages
    #         pager = portal_pager(
    #             url=f"/my/{mailbox}",
    #             total=50,  # You might want to replace this with actual count
    #             page=page,
    #             step=self._items_per_page
    #         )
    #         emails_placeholder = [{"uid": 1, "subject": "Test Email 1", "date": "2023-01-01 10:00:00"}, {"uid": 2, "subject": "Test Email 2", "date": "2023-01-02 11:00:00" }]
    #         values.update({
    #             'emails': emails_placeholder,
    #             'page_name': 'email',
    #             'default_url': f'/my/{mailbox}',
    #             'pager': pager,
    #             'mailbox': mailbox,  # You can use this in your view to highlight the active mailbox
    #         })

    #     return request.render("mail_portal.portal_my_emails", values)

    @http.route(['/my/<string:mailbox>', '/my/<string:mailbox>/page/<int:page>'], type='http', auth='user', website=True)
    def portal_mailbox(self, mailbox='inbox', page=1, **kw):
        values = self._prepare_portal_layout_values()
    
        current_user_partner_id = request.env.user.partner_id.id
        # CHANGE TO THE THREAD
        threads = request.env['portal.email.thread'].sudo().get_threads(current_user_partner_id, mailbox)
    
            # Paginate the threads
        pager = portal_pager(
            url=f"/my/{mailbox}",
            total=len(threads),
            page=page,
            step=self._items_per_page
        )

        start = (page - 1) * self._items_per_page
        end = start + self._items_per_page
        paginated_threads = threads[start:end]

        values.update({
            'emails': paginated_threads,
            'page_name': 'email',
            'default_url': f'/my/{mailbox}',
            'pager': pager,
            'mailbox': mailbox,
        })
    
        return request.render("mail_portal.portal_my_emails", values)


    @http.route(['/my/<string:mailbox>/d/<string:email_id>'], type='http', auth='user', website=True)
    def portal_email(self, mailbox, email_id, **kw):
        values = self._prepare_portal_layout_values()
        
        current_user_partner_id = request.env.user.partner_id.id
        record = request.env['portal.fetchmail'].sudo().search([('partner_id', '=', current_user_partner_id)], limit=1)

        _logger.debug("[OLEK][MAIN]:portal_email mailbox %s", mailbox)
        _logger.debug("[OLEK][MAIN]:portal_email record %s", record)


        if record:
            email_details = record.fetch_mail_thread(mailbox, email_id)

            _logger.debug("[OLEK][MAIN]:portal_email email_details %s", email_details)
            values.update({
                'email_details': email_details,
                'page_name': 'email',
                'default_url': f'/my/{mailbox}',
                'mailbox': mailbox
            })
        return request.render("mail_portal.portal_email_details", values)


    # @http.route(['/my/emails', '/my/emails/page/<int:page>'], type='http', auth="user", website=True)
    # def portal_my_emails(self, page=1, **kw):
    #     values = self._prepare_portal_layout_values()

    #     # Fetch stored emails from the database instead of using hardcoded values
    #     Email = request.env['portal.email.message']
    #     domain = []  # Add your domain filters as needed
    #     emails = Email.search(domain, order='date desc')  # Adjust the search as needed

    #     # Use the pager for real navigation through pages
    #     pager = portal_pager(
    #         url="/my/emails",
    #         total=Email.search_count(domain),
    #         page=page,
    #         step=self._items_per_page
    #     )
    #     values.update({
    #         'emails': emails,
    #         'page_name': 'email',
    #         'default_url': '/my/emails',
    #         'pager': pager,
    #     })

    #     _logger.debug("[OLEK][MAIN]:portal_my_emails emails %s", emails)

    #     return request.render("mail_portal.portal_my_emails", values)


    @http.route(['/my/fetch_emails'], type='http', auth="user", website=True)
    def fetch_emails(self, **kw):

        current_user_partner_id = request.env.user.partner_id.id
        record = request.env['portal.fetchmail'].sudo().search([('partner_id', '=', current_user_partner_id)], limit=1)

        if record:
            # Trigger the fetch_mail method on the record
            record.fetch_mail()

        # Redirect back to the email list page
        return request.redirect("/my/emails")



    # def _prepare_portal_layout_values(self):
    #     values = super()._prepare_portal_layout_values()
    #     # Add your code here to count emails, etc.
    #     values['email_count'] = request.env['custom.email'].search_count([('recipient', '=', request.env.user.partner_id.id)])
    #     _logger.debug("[OLEK][MAIN]:_prepare_portal_layout_values values %s", values)
    #     return values

    # @http.route(['/my/emails', '/my/emails/page/<int:page>'], type='http', auth="user", website=True)
    # def portal_my_emails(self, page=1, **kw):
    #     values = self._prepare_portal_layout_values()
    #     # Email = request.env['mail.message']
    #     CustomEmail = request.env['custom.email']

    #     domain = [('author_id', '=', request.env.user.partner_id.id)]  # Sample domain, change as needed

    #     # email count
    #     email_count = CustomEmail.search_count(domain)
    #     # pager
    #     pager = portal_pager(
    #         url="/my/emails",
    #         total=email_count,
    #         page=page,
    #         step=self._items_per_page
    #     )

    #     # content according to pager and archive selected
    #     emails = CustomEmail.search(domain, limit=self._items_per_page, offset=pager['offset'])
    #     values.update({
    #         'emails': emails.sudo(),
    #         'page_name': 'email',
    #         'default_url': '/my/emails',
    #         'pager': pager,
    #     })
    #     return request.render("mail_portal.portal_my_emails", values)





    # @http.route(['/my/emails/<int:email_id>'], type='http', auth="user", website=True)
    # def portal_my_email(self, email_id, **kw):
    #     try:
    #         # email_sudo = request.env['mail.message'].sudo().browse(email_id)
    #         email_sudo = request.env['custom.email'].sudo().browse(email_id)

    #         # Ensure the user has access to this email, you can add more sophisticated checks
    #         if email_sudo.author_id != request.env.user.partner_id:
    #             return request.redirect('/my/emails')
    #     except Exception as e:
    #         return request.redirect('/my/emails')

    #     _logger.info("[mail_portal][http.route(['/my/emails/<int:email_id>']] Email found %s", email_sudo)
    #     values = {
    #         'email': email_sudo,
    #         'page_name': 'email_detail',
    #     }
    #     return request.render("mail_portal.portal_my_email", values)
