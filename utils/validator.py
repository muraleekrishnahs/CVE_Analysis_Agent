import re

def validate_cve_id(cve_id):
    """
    Validate the format of a CVE ID.
    Expected format: CVE-YYYY-NNNNN (where YYYY is year and NNNNN is a sequence number)
    
    Args:
        cve_id (str): The CVE ID to validate
        
    Returns:
        bool: True if the ID is valid, False otherwise
    """
    # Check Regular expression pattern for CVE ID format
    pattern = r'^CVE-\d{4}-\d{4,}$'
    
    return bool(re.match(pattern, cve_id)) 