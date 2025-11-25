# web-vulnerabilities-scanner/main.py

import argparse
import sys
from core.crawler import Crawler
from modules.sql_scanner import sql_scanner
# from modules import sql_scanner, xss_scanner
# from reporting import console_reporter

def main():
    """
    The main function of the program. It parses command-line arguments,
    initializes the crawler, and starts the scanning process.
    """
    parser = argparse.ArgumentParser(description="Web Vulnerabilities Scanner")
    parser.add_argument(
        "-u", "--url", 
        required=True, 
        help="The target URL to scan (e.g., http://localhost:8080)"
    )
    args = parser.parse_args()

    print(f"[*] Starting scan for target: {args.url}")

    try:
        # Create an instance of our crawler
        crawler = Crawler(args.url)
        # Run the main crawl method to collect targets
        targets = crawler.crawl()
        
        print("\n[+] Crawling process finished.")
        if targets:
            print("[+] Discovered dynamic targets:")
            for i, target in enumerate(targets, 1):
                print(f"  {i}. {target}")
        else:
            # This is expected for now, as we haven't implemented request interception yet
            print("[+] No dynamic targets (like forms) were found for further scanning.")
            
        # TODO: In the future, we will pass 'targets' to the scanning modules
        # all_findings = []
        # for target in targets:
        #     all_findings.extend(sql_scanner.scan(target))
        #     all_findings.extend(xss_scanner.scan(target))
        #
        # console_reporter.display_report(all_findings)

    except Exception as e:
        print(f"\n[!!!] A critical error occurred: {e}")

# A standard Python idiom that ensures the main() function is called
# only when the script is executed directly.
if __name__ == "__main__":
    main()