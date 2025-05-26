import argparse
import logging
import requests
import socket
import re
import sys
from bs4 import BeautifulSoup
import whois

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_domain(domain):
    """
    Checks if a domain is valid using regex and DNS resolution.
    """
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$", domain):
        return False
    try:
        socket.gethostbyname(domain)  # Attempt DNS resolution
        return True
    except socket.gaierror:
        return False


def check_bucket_access(bucket_url):
    """
    Checks if a bucket is publicly accessible with list/read permissions.
    Returns True if accessible, False otherwise.
    """
    try:
        response = requests.get(bucket_url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Check for common S3 listing vulnerabilities
        if "ListBucketResult" in response.text:
            logging.info(f"Bucket {bucket_url} is publicly listable.")
            return True

        # Check for common GCS listing vulnerabilities -  This is a simplified check. Real-world GCS checks might need API calls
        if "Contents" in response.text and "Name" in response.text:  #Basic heuristic
            logging.info(f"Bucket {bucket_url} appears to be publicly readable (GCS).")
            return True
        
        #Check for Azure Blob Storage
        if "EnumerationResults" in response.text:
            logging.info(f"Bucket {bucket_url} appears to be publicly listable (Azure).")
            return True
        
        # Check for common error messages indicating access denied. Better heuristics are needed
        if "AccessDenied" in response.text or "NoSuchBucket" in response.text:
            logging.debug(f"Bucket {bucket_url} is likely not publicly accessible or doesn't exist.  Received: {response.text[:100]}...") #Only show the first 100 char
            return False
        

        # If none of the above conditions are met, assume the bucket is not publicly accessible
        logging.debug(f"Bucket {bucket_url} does not appear to be publicly accessible. Received: {response.text[:100]}...")

        return False

    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking bucket {bucket_url}: {e}")
        return False

def generate_bucket_names(domain):
    """
    Generates a list of common bucket naming conventions based on the domain.
    """
    return [
        f"{domain}-bucket",
        f"bucket-{domain}",
        f"{domain}",
        f"{domain.replace('.', '-')}",
        f"{domain}-public",
        f"public-{domain}"
    ]

def scan_domain(domain):
    """
    Scans a domain for publicly accessible cloud storage buckets.
    """
    if not is_valid_domain(domain):
        logging.error(f"Invalid domain: {domain}")
        return

    bucket_names = generate_bucket_names(domain)
    accessible_buckets = []

    for bucket_name in bucket_names:
        # Define the potential bucket URLs for different cloud providers
        bucket_urls = [
            f"https://{bucket_name}.s3.amazonaws.com", # AWS S3
            f"https://storage.googleapis.com/{bucket_name}", # Google Cloud Storage
            f"https://{bucket_name}.blob.core.windows.net" #Azure Blob Storage
        ]
        
        for bucket_url in bucket_urls:
            if check_bucket_access(bucket_url):
                accessible_buckets.append(bucket_url)

    if accessible_buckets:
        print(f"\nPublicly accessible buckets found for domain {domain}:")
        for bucket_url in accessible_buckets:
            print(f"- {bucket_url}")
    else:
        print(f"No publicly accessible buckets found for domain {domain}.")


def setup_argparse():
    """
    Sets up the command-line argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans a domain for publicly accessible cloud storage buckets.")
    parser.add_argument("domain", help="The domain to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    return parser

def main():
    """
    Main function to execute the bucket scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scan_domain(args.domain)


if __name__ == "__main__":
    main()