/** @odoo-module **/

import publicWidget from "@web/legacy/js/public/public_widget";

publicWidget.registry.EmailHoverWidget = publicWidget.Widget.extend({
    selector: '.o_mail_portal_email_from',
    events: {
        'mouseenter': '_onMouseEnter',
        'mouseleave': '_onMouseLeave',
    },

    /**
     * @override
     */
    start: function () {
        var def = this._super.apply(this, arguments);
        // Any additional initialization code can go here
        return def;
    },

    // Handlers
    _onMouseEnter: function(ev) {
        var $target = $(ev.currentTarget);
        $target.find('.o_email-display-name').addClass('d-none');
        $target.find('.o_email-address').removeClass('d-none');
    },

    _onMouseLeave: function(ev) {
        var $target = $(ev.currentTarget);
        $target.find('.o_email-address').addClass('d-none');
        $target.find('.o_email-display-name').removeClass('d-none');
    },
});
