const axios = require('axios')
const { table } = require('table')

// config for table
const config = {
  columns: {
    0: { width: 50 },
    1: { width: 60 },  // column 1 max width (characters)
  }
};
const config_outer = {
  columns: {
    // 0: { width: 54 },
    1: { width: 117 },
  }
};

class HeadScan {
    constructor() {
        this.securityHeaders = {
            'Strict-Transport-Security': 'Enforces HTTPS', 
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Content-Security-Policy': 'Prevents XSS attacks',
            'X-Permitted-Cross-Domain-Policies': 'Restricts cross-domain policy file loading',
            'Referrer-Policy': 'Controls referrer information',
            'Clear-Site-Data': 'Requests browser to clear stored data for the site',
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
            'X-XSS-Protection': 'Replaced by Content-Security-Policy header',
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
            }
        }
    }

    analyzeHeaders(url, headers, statusCode) {
        const results = {
            url,
            statusCode,
            headersFound: {},
            missingHeaders: [],
            deprecatedHeadersFound: [],
        };

        // check security headers
        for (const [header, description] of Object.entries(this.securityHeaders)) {
            if (headers[header.toLowerCase()] !== undefined) {
                results.headersFound[header] = {
                    value: headers[header.toLowerCase()],
                    description: description
                };
            }
            else {
                results.missingHeaders.push(header);
            }
        }

        // check deprecated headers
        for (const header of Object.keys(this.deprecatedSecurityHeaders)) {
            if (headers[header.toLowerCase()] !== undefined) {
                results.deprecatedHeadersFound.push(header);
            }
        }

        return results;
    }

    displayResults(results) {
        const result_table = [[
            'URL',
            'Found',
            'Missing',
            'Deprecated'
        ]];
        const result_detail_table = {};
        const display_table = [['URL', 'Result']];

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
                    result.missingHeaders.length,
                    result.deprecatedHeadersFound.length
                ]);
                
                result_detail_table[result.url] = {};
                result_detail_table[result.url]['found'] = [['Header', 'Value']];
                for (const [headerName, value] of Object.entries(result.headersFound)) {
                    result_detail_table[result.url]['found'].push([headerName, value['value']]);
                }

                result_detail_table[result.url]['missing'] = [['Header', 'Description']];
                for (const headerName of result.missingHeaders) {
                    let description = this.securityHeaders[headerName];
                    result_detail_table[result.url]['missing'].push([headerName, description]);
                }

                result_detail_table[result.url]['deprecated'] = [['Header', 'Description']];
                for (const headerName of result.deprecatedHeadersFound) {
                    let description = this.deprecatedSecurityHeaders[headerName];
                    result_detail_table[result.url]['deprecated'].push([headerName, description]);
                }

                display_table.push([result.url, "Found Headers\n" + table(result_detail_table[result.url]['found'], config) + "\nMissing Headers\n" + table(result_detail_table[result.url]['missing'], config) + "\nDeprecated Headers\n" + table(result_detail_table[result.url]['deprecated'], config)])
            }
        });

        console.log("\nScan Summary:")
        console.log(table(result_table));

        console.log("Scan detail:");
        console.log(table(display_table, config_outer));
    }
}

module.exports = HeadScan;