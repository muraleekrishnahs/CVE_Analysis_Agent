import os
import json
import sqlite3
from typing import Dict, List, Any, Optional
import datetime

class DBManager:
    """
    Database manager for storing and retrieving CVE data
    """
    def __init__(self, db_path="cve_database.db"):
        """
        Initialize the database connection and create tables if they don't exist
        
        Args:
            db_path (str): Path to the SQLite database file
        """
        self.db_path = db_path
        self.vector_support_initialized = False
        self._create_tables()
    
    def _create_connection(self):
        """Create a database connection"""
        try:
            conn = sqlite3.connect(self.db_path)
            return conn
        except sqlite3.Error as e:
            print(f"Error connecting to database: {e}")
            return None
    
    def _create_tables(self):
        """Create the necessary tables if they don't exist"""
        conn = self._create_connection()
        if conn:
            cursor = conn.cursor()
            
            # Create CVE table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                summary TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                last_modified_date TEXT,
                created_at TEXT NOT NULL,
                sources TEXT
            )
            ''')
            
            # Load sqlite-vec extension if available
            has_vector_support = self._load_vector_extension(conn)
            
            # Create vector embeddings table using vec0 virtual table
            if has_vector_support:
                try:
                    cursor.execute('''
                    CREATE VIRTUAL TABLE IF NOT EXISTS cve_embeddings USING vec0(
                        embedding FLOAT[1536]
                    )
                    ''')
                    if not hasattr(self, 'vector_table_created'):
                        self.vector_table_created = True
                        
                except sqlite3.OperationalError as e:
                    if not hasattr(self, 'vector_table_error_reported'):
                        print(f"Warning: Could not create vector embedding table. Vector similarity search will be disabled: {e}")
                        self.vector_table_error_reported = True
            
            # Keep old keyword table for backward compatibility
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_keywords (
                cve_id TEXT,
                keyword TEXT,
                PRIMARY KEY (cve_id, keyword),
                FOREIGN KEY (cve_id) REFERENCES cves(id)
            )
            ''')
            
            conn.commit()
            conn.close()
    
    def store_cve(self, cve_id: str, cve_data: Dict[Any, Any]) -> bool:
        """
        Store CVE data in the database
        
        Args:
            cve_id (str): The CVE ID
            cve_data (dict): The CVE data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Extract data from the CVE data
            cve = cve_data["cve"]
            
            # Get basic CVE information
            published_date = cve.get("published")
            last_modified_date = cve.get("lastModified")
            
            # Get descriptions
            description = ""
            if "descriptions" in cve and cve["descriptions"]:
                for desc in cve["descriptions"]:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
            
            # Get severity and CVSS score
            severity = "Unknown"
            cvss_score = 0.0
            
            metrics = cve.get("metrics", {})
            # Try to get CVSS v3 score first, fall back to v2
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "Unknown")
                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                severity = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseSeverity", "Unknown")
                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)
                # Map CVSS v2 score to severity
                if cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            # Get sources
            sources = ",".join(cve_data.get("_sources", ["NVD"]))
            
            # Insert into CVEs table
            cursor.execute(
                '''
                INSERT OR REPLACE INTO cves 
                (id, data, summary, severity, cvss_score, published_date, last_modified_date, created_at, sources)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    cve_id,
                    json.dumps(cve_data),
                    description,
                    severity,
                    cvss_score,
                    published_date,
                    last_modified_date,
                    datetime.datetime.now().isoformat(),
                    sources
                )
            )
            
            # Extract keywords for backwards compatibility
            keywords = self._extract_keywords(cve_data)
            
            # Delete existing keywords
            cursor.execute("DELETE FROM cve_keywords WHERE cve_id = ?", (cve_id,))
            
            # Insert keywords
            for keyword in keywords:
                cursor.execute(
                    "INSERT INTO cve_keywords (cve_id, keyword) VALUES (?, ?)",
                    (cve_id, keyword)
                )
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error storing CVE: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    def _load_vector_extension(self, conn):
        """
        Helper method to load the SQLite vector extension
        
        Args:
            conn: SQLite connection
            
        Returns:
            bool: True if successfully loaded, False otherwise
        """
        try:
            conn.enable_load_extension(True)
            import sqlite_vec
            sqlite_vec.load(conn)
            
            # Verify extension is loaded
            cursor = conn.cursor()
            cursor.execute("SELECT vec_version()")
            version = cursor.fetchone()[0]
            
            if not self.vector_support_initialized:
                self.vector_support_initialized = True
                
            return True
        except (ImportError, sqlite3.OperationalError, Exception) as e:
            if not self.vector_support_initialized:
                print(f"Warning: Could not load sqlite-vec extension: {e}")
            return False
            
    def _get_cve_integer_id(self, cve_id: str) -> int:
        """
        Convert a CVE ID string to an integer hash for use with vector tables
        
        Args:
            cve_id (str): The CVE ID (e.g., CVE-2023-1234)
            
        Returns:
            int: Integer representation of the CVE ID
        """
        # Use a simple hash function to convert the string to a positive integer
        # Python's hash() can return negative values, so we ensure it's positive
        return abs(hash(cve_id)) % (2**31 - 1)  # Limit to 31-bit positive integer
    
    def store_cve_embedding(self, cve_id: str, embedding: List[float]) -> bool:
        """
        Store CVE embedding vector in the database
        
        Args:
            cve_id (str): The CVE ID
            embedding (List[float]): The embedding vector
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Load vector extension
            if not self._load_vector_extension(conn):
                # Only log this message once per session
                if not hasattr(self, 'vector_extension_unavailable_logged'):
                    print("Vector extension not available. Skipping embedding storage.")
                    self.vector_extension_unavailable_logged = True
                return False
            
            # Test if vec0 module exists by checking table existence
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_embeddings'")
            if not cursor.fetchone():
                # Only log this message once per session
                if not hasattr(self, 'vector_table_missing_logged'):
                    print("Warning: cve_embeddings table does not exist. Vector storage disabled.")
                    self.vector_table_missing_logged = True
                return False
            
            # Format embedding as JSON
            embedding_json = json.dumps(embedding)
            
            # Convert CVE ID to integer for vector table primary key
            int_id = self._get_cve_integer_id(cve_id)
            
            # Store the mapping from integer ID to CVE ID if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_id_mapping (
                    int_id INTEGER PRIMARY KEY,
                    cve_id TEXT UNIQUE,
                    FOREIGN KEY (cve_id) REFERENCES cves(id)
                )
            ''')
            
            # Insert or update the mapping
            cursor.execute(
                "INSERT OR REPLACE INTO cve_id_mapping (int_id, cve_id) VALUES (?, ?)",
                (int_id, cve_id)
            )
            
            # First check if we have an embedding for this CVE already
            cursor.execute("SELECT rowid FROM cve_embeddings WHERE rowid = ?", (int_id,))
            result = cursor.fetchone()
            
            if result:
                # Update existing embedding
                cursor.execute(
                    "UPDATE cve_embeddings SET embedding = ? WHERE rowid = ?",
                    (embedding_json, int_id)
                )
            else:
                # Insert new embedding
                cursor.execute(
                    "INSERT INTO cve_embeddings(rowid, embedding) VALUES (?, ?)",
                    (int_id, embedding_json)
                )
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error storing CVE embedding: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    def get_cve(self, cve_id: str) -> Optional[Dict[Any, Any]]:
        """
        Retrieve CVE data from the database
        
        Args:
            cve_id (str): The CVE ID
            
        Returns:
            dict: The CVE data, or None if not found
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT data FROM cves WHERE id = ?", (cve_id,))
            result = cursor.fetchone()
            
            if result:
                return json.loads(result[0])
            return None
        except Exception as e:
            print(f"Error retrieving CVE: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    def find_similar_cves(self, cve_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Find similar CVEs based on vector embedding similarity
        
        Args:
            cve_id (str): The CVE ID to find similar CVEs for
            limit (int): Maximum number of similar CVEs to return
            
        Returns:
            list: List of dictionaries with CVE IDs and similarity percentages
        """
        try:
            conn = self._create_connection()
            if not conn:
                return []
                
            cursor = conn.cursor()
            
            # Check if the vector table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_embeddings'")
            if not cursor.fetchone():
                print("Vector embeddings table doesn't exist")
                return []
                
            # Load vector extension
            if not self._load_vector_extension(conn):
                print("Vector extension not available")
                return []
                
            # Convert CVE ID to integer ID
            int_id = self._get_cve_integer_id(cve_id)
            
            # Get the embedding for the input CVE
            cursor.execute("SELECT embedding FROM cve_embeddings WHERE rowid = ?", (int_id,))
            result = cursor.fetchone()
            
            if not result:
                print(f"No embedding found for {cve_id}")
                return []
                
            embedding = result[0]
            
            try:
                # Find similar CVEs using vector search
                query = f"""
                SELECT 
                    rowid, 
                    distance 
                FROM cve_embeddings 
                WHERE embedding MATCH ? AND rowid != ? AND k=?
                ORDER BY distance
                """
                
                cursor.execute(query, (embedding, int_id, limit))
                similar_results = cursor.fetchall()
                
                if not similar_results:
                    return []
                    
                # Process results with similarity percentages
                similar_cves_with_similarity = []
                for row_id, distance in similar_results:
                    # Convert distance to similarity percentage (distance is 0-2 range, where 0 is identical)
                    # Convert to a 0-100% scale where 100% is identical
                    similarity_percentage = min(100, max(0, (1 - distance/2) * 100))
                    
                    # Get the CVE ID from the mapping table
                    cursor.execute("SELECT cve_id FROM cve_id_mapping WHERE int_id = ?", (row_id,))
                    cve_id_result = cursor.fetchone()
                    
                    if cve_id_result:
                        similar_cves_with_similarity.append({
                            "cve_id": cve_id_result[0],
                            "similarity": similarity_percentage
                        })
                
                return similar_cves_with_similarity
            except sqlite3.OperationalError as e:
                print(f"Vector search query failed: {e}")
                return []
        except Exception as e:
            print(f"Error finding similar CVEs: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_cves_by_source(self, source: str) -> List[str]:
        """
        Get all CVEs from a specific source
        
        Args:
            source (str): The source name
            
        Returns:
            list: List of CVE IDs from the source
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM cves WHERE sources LIKE ?", (f"%{source}%",))
            
            cve_ids = [row[0] for row in cursor.fetchall()]
            return cve_ids
        except Exception as e:
            print(f"Error getting CVEs by source: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    def _extract_keywords(self, cve_data: Dict[Any, Any]) -> List[str]:
        """
        Extract keywords from CVE data for similarity search
        
        Args:
            cve_data (dict): The CVE data
            
        Returns:
            list: List of keywords
        """
        keywords = set()
        cve = cve_data["cve"]
        
        # Add CVE ID parts
        cve_id = cve.get("id", "")
        if cve_id:
            keywords.add(cve_id)
            parts = cve_id.split("-")
            if len(parts) >= 3:
                keywords.add(parts[1])  # Year
        
        # Add description words
        if "descriptions" in cve and cve["descriptions"]:
            for desc in cve["descriptions"]:
                if desc.get("lang") == "en":
                    description = desc.get("value", "").lower()
                    # Split description into words and filter out common words
                    stop_words = {"a", "an", "the", "and", "or", "but", "is", "are", "was", "were", "be", "being", "been", "to", "of", "in", "for", "with", "on", "at", "by", "from"}
                    words = [word.strip(".,;:?!()[]{}\"'") for word in description.split()]
                    words = [word for word in words if word and len(word) > 2 and word not in stop_words]
                    keywords.update(words)
        
        # Add vulnerability types and product names
        if "configurations" in cve_data:
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        if cpe:
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                keywords.add(parts[3])  # Vendor
                                keywords.add(parts[4])  # Product
        
        # Add CVE metrics data
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            keywords.add(metrics["cvssMetricV31"][0].get("cvssData", {}).get("attackVector", ""))
            keywords.add(metrics["cvssMetricV31"][0].get("cvssData", {}).get("attackComplexity", ""))
        
        # Add data from additional sources
        if "_additional_sources" in cve_data:
            # Add CWE information from CIRCL if available
            if "CIRCL" in cve_data["_additional_sources"]:
                circl_data = cve_data["_additional_sources"]["CIRCL"]
                if "_source_data" in circl_data and "cwe" in circl_data["_source_data"]:
                    cwe = circl_data["_source_data"]["cwe"]
                    if isinstance(cwe, str):
                        keywords.add(cwe)
                    elif isinstance(cwe, list):
                        keywords.update(cwe)
        
        # Filter out empty strings and limit keyword length
        keywords = {k for k in keywords if k and len(k) < 50}
        
        return list(keywords) 