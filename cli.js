const HeadScan = require('./scanner');
const scanner = new HeadScan();

async function main() {
    const urls = process.argv.slice(2);

    if (urls.length === 0) {
        console.log('Usage: node cli.js <url1> <url2> ...');
        process.exit(1);
    }

    const scanPromises = urls.map(url => scanner.scanUrl(url));
    const results = await Promise.all(scanPromises);

    scanner.displayResults(results);
}

main().catch(console.error);