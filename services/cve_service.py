import requests
import json
from datetime import datetime
import time
from typing import Dict, Any, List, Optional
import concurrent.futures

class CVEDataSource:
    """Base class for CVE data sources"""
    def fetch_cve(self, cve_id: str) -> Optional[Dict[Any, Any]]:
        """Fetch CVE data from the source"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def get_source_name(self) -> str:
        """Get the name of the data source"""
        raise NotImplementedError("Subclasses must implement this method")

class NVDDataSource(CVEDataSource):
    """NIST National Vulnerability Database data source"""
    def get_source_name(self) -> str:
        return "NVD"
    
    def fetch_cve(self, cve_id: str) -> Optional[Dict[Any, Any]]:
        """
        Fetch CVE details from the NIST National Vulnerability Database.
        
        Args:
            cve_id (str): The CVE ID to fetch
            
        Returns:
            dict: Parsed CVE data or None if not found
        """
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        try:
            response = requests.get(url)
            response.raise_for_status()
            
            data = response.json()
            
            if "vulnerabilities" not in data or not data["vulnerabilities"]:
                return None
            
            result = data["vulnerabilities"][0]
            result["_source"] = self.get_source_name()
            return result
        except requests.exceptions.RequestException as e:
            return None
        except json.JSONDecodeError:
            return None
        except Exception as e:
            return None

class MITREDataSource(CVEDataSource):
    """MITRE CVE database data source"""
    def get_source_name(self) -> str:
        return "MITRE"
    
    def fetch_cve(self, cve_id: str) -> Optional[Dict[Any, Any]]:
        """
        Fetch CVE details from the MITRE CVE database.
        
        Args:
            cve_id (str): The CVE ID to fetch
            
        Returns:
            dict: Parsed CVE data or None if not found
        """
        # MITRE CVE API URL
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        
        try:
            response = requests.get(url)
            
            # Check if we got a successful response
            if response.status_code == 200:
                data = response.json()
                
                # Format MITRE data to be compatible with our expected schema
                formatted_data = {
                    "cve": {
                        "id": cve_id,
                        "published": data.get("datePublished", ""),
                        "lastModified": data.get("dateUpdated", ""),
                        "descriptions": []
                    },
                    "_source": self.get_source_name(),
                    "_source_data": data
                }
                
                # Add description if available
                if "descriptions" in data and data["descriptions"]:
                    for desc in data["descriptions"]:
                        if desc.get("lang") == "en":
                            formatted_data["cve"]["descriptions"].append({
                                "lang": "en",
                                "value": desc.get("value", "")
                            })
                
                return formatted_data
            else:
                return None
        except requests.exceptions.RequestException as e:
            return None
        except json.JSONDecodeError:
            return None
        except Exception as e:
            return None

class CIRCLDataSource(CVEDataSource):
    """CIRCL CVE Search data source"""
    def get_source_name(self) -> str:
        return "CIRCL"
    
    def fetch_cve(self, cve_id: str) -> Optional[Dict[Any, Any]]:
        """
        Fetch CVE details from the CIRCL CVE Search API.
        
        Args:
            cve_id (str): The CVE ID to fetch
            
        Returns:
            dict: Parsed CVE data or None if not found
        """
        # CIRCL CVE Search API URL
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        
        try:
            response = requests.get(url)
            
            # Check if we got a successful response
            if response.status_code == 200:
                data = response.json()
                
                # Format CIRCL data to be compatible with our expected schema
                formatted_data = {
                    "cve": {
                        "id": cve_id,
                        "published": data.get("Published", ""),
                        "lastModified": data.get("Modified", ""),
                        "descriptions": [{
                            "lang": "en",
                            "value": data.get("summary", "")
                        }]
                    },
                    "_source": self.get_source_name(),
                    "_source_data": data
                }
                return formatted_data
            else:
                return None
        except requests.exceptions.RequestException as e:
            return None
        except json.JSONDecodeError:
            return None
        except Exception as e:
            return None

class GithubSecurityAdvisoriesDataSource(CVEDataSource):
    """GitHub Security Advisories data source"""
    def get_source_name(self) -> str:
        return "GitHub"
    
    def fetch_cve(self, cve_id: str) -> Optional[Dict[Any, Any]]:
        """
        Fetch CVE-related information from GitHub Security Advisories API.
        
        Args:
            cve_id (str): The CVE ID to fetch
            
        Returns:
            dict: Parsed CVE data or None if not found
        """
        # GitHub Search API to find repositories mentioning this CVE
        url = f"https://api.github.com/search/repositories?q={cve_id}&sort=stars&order=desc"
        
        try:
            response = requests.get(url)
            
            # Check if we got a successful response
            if response.status_code == 200:
                data = response.json()
                
                if "items" in data and data["items"]:
                    # Format GitHub data to be compatible with our expected schema
                    formatted_data = {
                        "cve": {
                            "id": cve_id,
                            "descriptions": [{
                                "lang": "en",
                                "value": f"GitHub repositories that reference this CVE: {', '.join([repo['full_name'] for repo in data['items'][:5]])}"
                            }]
                        },
                        "_source": self.get_source_name(),
                        "_source_data": {
                            "repos": data["items"][:10],
                            "total_count": data["total_count"]
                        }
                    }
                    return formatted_data
                else:
                    return None
            else:
                return None
        except requests.exceptions.RequestException as e:
            return None
        except json.JSONDecodeError:
            return None
        except Exception as e:
            return None

class CVEDataSourceManager:
    """Manager for multiple CVE data sources"""
    def __init__(self):
        # Initialize data sources
        self.sources = [
            NVDDataSource(),
            MITREDataSource(),
            CIRCLDataSource(),
            GithubSecurityAdvisoriesDataSource()
        ]
    
    def fetch_from_all_sources(self, cve_id: str) -> Dict[str, Optional[Dict[Any, Any]]]:
        """
        Fetch CVE data from all configured data sources
        
        Args:
            cve_id (str): The CVE ID to fetch
            
        Returns:
            dict: Dictionary of data by source
        """
        # Results dictionary to store data from each source
        results = {}
        
        # Use ThreadPoolExecutor for concurrent API calls
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Map source names to futures
            future_to_source = {
                executor.submit(source.fetch_cve, cve_id): source 
                for source in self.sources
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    data = future.result()
                    results[source.get_source_name()] = data
                except Exception as e:
                    results[source.get_source_name()] = None
        
        return results
    
    def merge_cve_data(self, data_by_source: Dict[str, Optional[Dict[Any, Any]]]) -> Optional[Dict[Any, Any]]:
        """
        Merge CVE data from multiple sources
        
        Args:
            data_by_source: A dictionary mapping source names to their respective CVE data
            
        Returns:
            dict: Merged CVE data, or None if no valid data is available
        """
        # NVD is our primary source; if available, use it as the base
        if "NVD" in data_by_source and data_by_source["NVD"]:
            merged_data = data_by_source["NVD"].copy()
            merged_data["_sources"] = ["NVD"]
        else:
            # Try to find any valid data as the base
            base_data = None
            for source_name, data in data_by_source.items():
                if data:
                    base_data = data.copy()
                    base_data["_sources"] = [source_name]
                    break
            
            if not base_data:
                return None
            
            merged_data = base_data
        
        # Add information from additional sources
        merged_data["_additional_sources"] = {}
        
        for source_name, data in data_by_source.items():
            # Skip the primary source (already included in the base)
            if source_name in merged_data["_sources"]:
                continue
            
            # Skip empty data
            if not data:
                continue
            
            # Add this source to the list of sources
            merged_data["_sources"].append(source_name)
            
            # Store complete source data for reference
            merged_data["_additional_sources"][source_name] = data
            
            # Enhance the base data with additional information
            if "_source_data" in data:
                # Extract specific elements from the source data
                # This would be customized based on the structure of each source
                pass
            
            # Merge references if available
            if "references" in data.get("cve", {}) and "references" in merged_data.get("cve", {}):
                existing_urls = {ref.get("url") for ref in merged_data["cve"]["references"]}
                for ref in data["cve"]["references"]:
                    if ref.get("url") not in existing_urls:
                        merged_data["cve"]["references"].append(ref)
                        existing_urls.add(ref.get("url"))
        
        return merged_data

def fetch_cve_details(cve_id: str) -> Dict[Any, Any]:
    """
    Fetch CVE details from multiple sources and merge them
    
    Args:
        cve_id (str): The CVE ID to fetch
        
    Returns:
        dict: Merged CVE data
        
    Raises:
        Exception: If unable to fetch data from any source
    """
    # Initialize the data source manager
    manager = CVEDataSourceManager()
    
    # Fetch data from all sources
    data_by_source = manager.fetch_from_all_sources(cve_id)
    
    # Check how many sources returned data
    sources_with_data = [source for source, data in data_by_source.items() if data]
    
    # Merge the data
    merged_data = manager.merge_cve_data(data_by_source)
    
    if not merged_data:
        raise Exception(f"Unable to fetch data for {cve_id} from any source")
    
    # Store in database with embedding if importing database and llm_service is possible
    try:
        from database.db_manager import DBManager
        from services.llm_service import generate_cve_embedding
        
        # Initialize database manager
        db_manager = DBManager()
        
        # Store the CVE data
        db_manager.store_cve(cve_id, merged_data)
        
        # Generate and store embedding
        embedding = generate_cve_embedding(merged_data)
        if embedding:
            db_manager.store_cve_embedding(cve_id, embedding)
    except ImportError:
        # Database module not available, continue without storing
        pass
    except Exception as e:
        # Log error but don't fail
        print(f"Error storing CVE data in database: {e}")
    
    return merged_data 