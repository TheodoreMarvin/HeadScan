const axios = require('axios')

class HeadScan {
    constructor() {
        this.securityHeaders = {
            'Content-Security-Policy': 'Prevents XSS attacks',
            'Strict-Transport-Security': 'Enforces HTTPS', 
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features',
            'X-XSS-Protection': 'Legacy XSS protection'
        };
    }
}

module.exports = HeadScan;