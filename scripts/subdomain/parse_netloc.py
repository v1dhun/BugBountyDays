import sys
import argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

class URLParser:
    """
    To handle URL parsing and ensuring the URL starts with 'http://' if no scheme is provided.
    """
    def __init__(self, url, remove_port=False, remove_wildcard=False):
        self.url = url.strip()
        self.netloc = None
        self.remove_port = remove_port
        self.remove_wildcard = remove_wildcard

    def ensure_http(self):
        """
        Ensure the URL starts with 'http://' if no scheme is provided.
        """
        if not self.url.startswith(('http://', 'https://')):
            self.url = "http://" + self.url

    def parse_netloc(self):
        """
        Parse the URL and extract the netloc (domain with subdomains).
        If remove_port is True, remove the port number.
        If remove_wildcard is True, replace the wildcard subdomains ('*.' with '').
        """
        try:
            parsed = urlparse(self.url)
            if parsed.netloc:
                self.netloc = parsed.netloc
                if self.remove_port and ':' in self.netloc:
                    self.netloc = self.netloc.split(':')[0]
                if self.remove_wildcard and self.netloc.startswith('*'):
                    self.netloc = self.netloc.replace('*.', '')
            else:
                self.netloc = None
        except Exception as e:
            self.netloc = None
            print(f"Error parsing URL '{self.url}': {e}", file=sys.stderr)

    def get_netloc(self):
        """
        Return the netloc (domain) if it's valid, else return None.
        """
        return self.netloc

    def process(self):
        self.ensure_http()
        self.parse_netloc()


class URLProcessor:
    """
    To handle processing multiple URLs using parallel processing.
    """
    def __init__(self, urls, limit, remove_port=False, remove_wildcard=False):
        self.urls = urls
        self.limit = limit
        self.remove_port = remove_port
        self.remove_wildcard = remove_wildcard

    def process_urls(self):
        with ThreadPoolExecutor(max_workers=self.limit) as executor:
            results = list(executor.map(self.process_url, self.urls))
        return results

    def process_url(self, url):
        parser = URLParser(url, self.remove_port, self.remove_wildcard)
        parser.process()
        netloc = parser.get_netloc()
        if netloc:
            print(netloc)
        else:
            print(f"Invalid URL: {url}", file=sys.stderr)


def print_about():
    print("Reads a URL from stdin, ensures it starts with 'http://' (if no scheme),")
    print("and prints the domain (netloc) of the URL.")
    print("Example:")
    print("  echo 'example.com' | python3 parse_netloc.py --limit 4")
    print("Use '-nP' or '--no-port' to exclude the port from the domain.")
    print("Use '-rW' or '--remove-wildcard' to replace the netloc '*.' to ''.")


def main():
    parser = argparse.ArgumentParser(description="Extract the netloc (domain) from URLs provided via stdin.")
    parser.add_argument('--limit', type=int, default=4, help="Set the number of threads for parallel processing (default: 4).")
    parser.add_argument('-nP', '--no-port', action='store_true', help="Exclude the port from the netloc (if any).")
    parser.add_argument('-rW', '--remove-wildcard', action='store_true', help="Replace the netloc '*.' to ''.")
    parser.add_argument('--info', action='store_true', help="Show about information of the script usage.")
    args = parser.parse_args()

    if args.info:
        print_about()
        return

    inputs = [line.strip() for line in sys.stdin if line.strip()]
    
    if not inputs:
        print("No input provided.", file=sys.stderr)
        return

    processor = URLProcessor(inputs, args.limit, args.no_port, args.remove_wildcard)
    processor.process_urls()


if __name__ == "__main__":
    main()
