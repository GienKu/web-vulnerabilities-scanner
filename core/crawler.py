# web-vulnerabilities-scanner/core/crawler.py

from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright, Page, Request, Error

class Crawler:
    """
    Main class responsible for navigating the target website, discovering
    links, forms, and intercepting network requests.
    """

    def __init__(self, base_url: str):
        """
        Initializes the crawler with a starting URL.

        Args:
            base_url (str): The full URL of the website to be scanned.
        """
        self.start_url = base_url
        self.base_domain = urlparse(base_url).netloc
        
        self.urls_to_visit = {self.start_url}
        self.visited_urls = set()
        self.scan_targets = [] # A list of collected targets for scanning

    def _intercept_request(self, request: Request):
        """
        A callback function invoked by Playwright for every network request
        the page sends. Its job is to analyze the request and add it to
        'scan_targets' if it's interesting (e.g., a form submission).
        """
        if request.method != "GET":
             print(f"[+] Intercepted {request.method} request to: {request.url}")
        
        # TODO: Implement logic to save the target for scanning.
        # request.continue_() must be called to allow the request to proceed.

    def _discover_links(self, page: Page):
        """
        Finds all unique, valid links on the page that belong to the same domain.
        """
        links = page.locator('a').all()
        for link in links:
            href = link.get_attribute('href')

            # Skip empty, anchor, or javascript links
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue

            # Convert relative URLs (e.g., "/login.php") to absolute ones
            full_url = urljoin(page.url, href)

            # Check if the URL is within the scope of the target domain
            # and has not been visited or queued yet.
            if urlparse(full_url).netloc == self.base_domain:
                if full_url not in self.visited_urls and full_url not in self.urls_to_visit:
                    print(f"  [>] Discovered new link: {full_url}")
                    self.urls_to_visit.add(full_url)

    def _discover_and_submit_forms(self, page: Page):
        """
        Finds all forms on the page, fills them with mock data,
        and attempts to submit them.
        """
        raise NotImplementedError("'_discover_and_submit_forms' method is not yet implemented.")

    def crawl(self) -> list:
        """
        Main method to start the crawling process.
        It orchestrates the browser and calls other discovery methods.

        Returns:
            list: A list of discovered targets for further scanning.
        """
        print("[*] Starting the crawler...")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            page = browser.new_page()

            #  will enable this later
            # page.on("request", self._intercept_request)

            # Main crawling loop that runs as long as there are URLs to visit
            while self.urls_to_visit:
                url = self.urls_to_visit.pop()

                if url in self.visited_urls:
                    continue

                print(f"[*] Navigating to: {url}")
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=10000)
                    self.visited_urls.add(url)

                    # Discover new links on the current page
                    self._discover_links(page)
                    
                    # We'll enable this in a future step
                    # self._discover_and_submit_forms(page)

                except Error as e:
                    print(f"[!] Error navigating to {url}: {e}")

            print("[*] Closing the browser...")
            browser.close()
        
        print(f"[*] Crawler finished. Visited {len(self.visited_urls)} unique pages.")
        return self.scan_targets