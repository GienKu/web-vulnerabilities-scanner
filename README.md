# Web Vulnerabilities Scanner

![Project Status: In Development](https://img.shields.io/badge/status-in%20development-yellow) ![Language: Python](https://img.shields.io/badge/language-Python-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green)

An automated web application vulnerability scanner designed to identify common security flaws such as SQL Injection and Cross-Site Scripting. This is a university project focused on the practical application of cybersecurity principles in a controlled, educational environment.

## About The Project

Modern web applications are complex, often relying on dynamic content rendering and client-side JavaScript to function. This complexity makes traditional static scanners less effective. The Web Vulnerabilities Scanner aims to address this by using a headless browser to interact with web pages just as a user would. It can crawl dynamic sites, intelligently fill out forms to bypass client-side validation, and then launch modular security scans against the discovered endpoints.

The core mission of this project is to create a tool that understands the modern web and can serve as a foundational step in a security audit process.

### Key Features

*   **Dynamic Site Crawling:** Navigates through websites that heavily rely on JavaScript, using Playwright to discover links and interactive elements.
*   **Intelligent Form Submission:** Automatically analyzes form fields and uses mock data generation to satisfy client-side validation rules, ensuring that requests are sent and can be analyzed.
*   **Modular Scanner Architecture:** Each vulnerability type (SQLi, XSS) is handled by a separate module, making the tool easy to extend with new tests in the future.
*   **SQL Injection (SQLi) Detection:** Tests input fields and URL parameters for basic error-based SQL Injection vulnerabilities.
*   **Cross-Site Scripting (XSS) Detection:** Checks for reflected XSS vulnerabilities by injecting payloads and analyzing the server's response.
*   **Request Interception:** Captures AJAX/Fetch requests triggered by user interaction to discover hidden API endpoints.

### Built With

*   [Python](https://www.python.org/) - The core programming language.
*   [Playwright](https://playwright.dev/python/) - For headless browser automation and dynamic site interaction.
*   [Requests](https://requests.readthedocs.io/en/latest/) - For crafting and sending HTTP requests during the scanning phase.
*   [Beautiful Soup 4](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) - For parsing static HTML content.
*   [Faker](https://faker.readthedocs.io/en/master/) - For generating realistic data to fill forms.

---
## ⚠️ Ethical Disclaimer
This tool is intended for educational purposes only. Running a vulnerability scanner against websites without explicit, written permission from the owner is illegal and unethical.
DO NOT use this tool on any public or private websites that you do not own.
The author is not responsible for any misuse or damage caused by this program.
Always conduct testing in a controlled, isolated environment using applications designed to be vulnerable (e.g., DVWA, OWASP Juice Shop).
