#!/usr/bin/env python3
import argparse
import re
import sys
from utils.validator import validate_cve_id
from utils.env_loader import load_env
from services.cve_service import fetch_cve_details
from services.llm_service import generate_summary
from database.db_manager import DBManager

def main():
    # Load environment variables
    load_env()
    
    parser = argparse.ArgumentParser(description="CVE Analysis Agent")
    parser.add_argument("cve_id", type=str, help="CVE ID to analyze (format: CVE-YYYY-NNNNN)")
    parser.add_argument("--search", action="store_true", help="Search for similar CVEs")
    parser.add_argument("--sources", action="store_true", help="Display data sources used")
    
    args = parser.parse_args()
    
    # Validate CVE ID format
    if not validate_cve_id(args.cve_id):
        sys.exit(f"Error: Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN")
    
    # Initialize database connection
    db = DBManager()
    
    # Check if the CVE is already in the database
    stored_cve = db.get_cve(args.cve_id)
    if stored_cve:
        print(f"Found {args.cve_id} in database.")
        cve_data = stored_cve
    else:
        print(f"Retrieving {args.cve_id} from multiple sources...")
        try:
            cve_data = fetch_cve_details(args.cve_id)
            # Store in database
            db.store_cve(args.cve_id, cve_data)
        except Exception as e:
            sys.exit(f"Error retrieving CVE details: {e}")
    
    # Display data sources
    if args.sources and "_sources" in cve_data:
        print("\nData sources used:")
        for source in cve_data["_sources"]:
            print(f"- {source}")
    
    # Generate summary using LLM
    summary = generate_summary(cve_data)
    
    print("\n" + "="*50)
    print(f"SUMMARY FOR {args.cve_id}")
    print("="*50)
    print(summary)
    print("="*50)
    
    # Search for similar CVEs if requested
    if args.search:
        similar_cves = db.find_similar_cves(args.cve_id)
        if similar_cves:
            print("\nSimilar CVEs:")
            for cve in similar_cves:
                print(f"- {cve}")
        else:
            print("\nNo similar CVEs found.")

if __name__ == "__main__":
    main() 