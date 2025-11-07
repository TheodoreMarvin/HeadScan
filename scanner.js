const axios = require('axios')
const { table } = require('table')

// config for table
const config = {
  columns: {
    // 0: { width: 50 },
    1: { width: 80 },  // column 1 max width (characters)
  }
};

class HeadScan {
    constructor() {
        this.securityHeaders = {
            'Strict-Transport-Security': 'Enforces HTTPS', 
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Content-Security-Policy': 'Prevents XSS attacks',
            'X-Permitted-Cross-Domain-Policies': 'Restricts cross-domain policy file loading for plugins (Flash etc.)',
            'Referrer-Policy': 'Controls referrer information',
            'Clear-Site-Data': 'Requests browser to clear stored data (cookies, storage, cache) for the site',
            'Cross-Origin-Embedder-Policy': 'Controls which resources a document may embed cross-origin',
            'Cross-Origin-Opener-Policy': 'Isolates browsing contexts from other origins',
            'Cross-Origin-Resource-Policy': 'Restricts which origins may load a resource',
            'Cache-Control': 'Controls browser and intermediate cache behaviour',
            'X-DNS-Prefetch-Control': 'Controls DNS prefetching',
            'Permissions-Policy': 'Controls browser features'
        };
        this.deprecatedSecurityHeaders = {
            'Feature-Policy': 'Replaced by Permissions-Policy header',
            'Expect-CT': 'No longer needed, Chromium enforces CT by default',
            'Public-Key-Pins': 'Difficult to implement, high risk of accidental lockout',
            'X-XSS-Protection': 'Replaced by Content-Security-Polici header',
            'Pragma': 'Only used for HTTP/1.0 backwards compatibility, replaced by Cache-Control for HTTP/1.1'
        };
    }

    async scanUrl(url) {
        try {
            if (!url.startsWith('http')) {
                url = 'https://' + url;
            }

            console.log(`Scanning: ${url}`);

            const response = await axios.get(url, {
                timeout: 10000,
                maxRedirects: 5,
                validateStatus: null
            });

            return this.analyzeHeaders(url, response.headers, response.status);
        }
        catch (error) {
            return {
                url,
                error: error.message,
                score: 0,
                grade: 'F'
            }
        }
    }

    analyzeHeaders(url, headers, statusCode) {
        const results = {
            url,
            statusCode,
            headersFound: {},
            missingHeaders: [],
            // score: 0,
            // grade: 'F'
        };

        console.log(Object.keys(headers));

        // check security header
        for (const [header, description] of Object.entries(this.securityHeaders)) {
            if (headers[header.toLowerCase()] !== undefined) {
                console.log(`${header}: ${headers[header.toLowerCase()]}`)
                results.headersFound[header] = {
                    value: headers[header.toLowerCase()],
                    description: description
                };
            }
            else {
                results.missingHeaders.push(header);
            }
        }

        // calculate score
        const totalHeaders = Object.keys(this.securityHeaders).length;
        const foundHeaders = Object.keys(results.headersFound).length;
        // results.score = Math.round((foundHeaders / totalHeaders) * 100);
        // results.grade = this.calculateGrade(results.score);

        console.log("==========");
        console.log(results.missingHeaders);

        return results;
    }

    displayResults(results) {
        const result_table = [[
            'URL',
            'Found',
            'Missing'
        ]];
        const result_detail_table = [[
            'Header name',
            'Value'
        ]];

        results.forEach(result => {
            if (result.error) {
                result_table.push([
                    result.url,
                    'Error',
                    result.error
                ]);
            }
            else {
                result_table.push([
                    result.url,
                    Object.keys(result.headersFound).length,
                    result.missingHeaders.length
                ]);
                
                for (const [headerName, value] of Object.entries(result.headersFound)) {
                    result_detail_table.push([headerName, value['value']]);
                }
            }
        });

        console.log(table(result_table));
        console.log(table(result_detail_table, config));
    }
}

module.exports = HeadScan;