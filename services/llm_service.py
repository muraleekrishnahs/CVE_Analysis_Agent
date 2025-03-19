import os
import json
from typing import Dict, Any, List
from openai import OpenAI

class LLMProvider:
    """Base class for LLM providers"""
    def generate_text(self, prompt: str) -> str:
        raise NotImplementedError("Subclasses must implement this method")
    
    def generate_embedding(self, text: str) -> List[float]:
        raise NotImplementedError("Subclasses must implement this method")

class OpenAIProvider(LLMProvider):
    """OpenAI API integration using the latest client"""
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise Exception("ERROR: No OpenAI API key found in environment variables. Please set OPENAI_API_KEY.")
        self.client = OpenAI(api_key=self.api_key)
        
    def generate_text(self, prompt: str) -> str:
        try:
            response = self.client.responses.create(
                model="gpt-4o",
                input=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability analysis."},
                    {"role": "user", "content": prompt}
                ]
            )
            # Extract the text from the response
            return response.output[0].content[0].text.strip()
        except Exception as e:
            raise Exception(f"Error calling OpenAI Responses API: {e}")
    
    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate an embedding vector for the given text using OpenAI's embeddings API
        
        Args:
            text (str): The text to generate an embedding for
            
        Returns:
            List[float]: The embedding vector
        """
        try:
            response = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=text,
                dimensions=1536,
                encoding_format="float"
            )
            return response.data[0].embedding
        except Exception as e:
            raise Exception(f"Error generating embedding with OpenAI API: {e}")

def format_cve_for_prompt(cve_data: Dict[Any, Any]) -> str:
    """
    Format CVE data into a readable format for the LLM prompt
    
    Args:
        cve_data: The CVE data from the multiple sources
        
    Returns:
        str: Formatted CVE data
    """
    cve = cve_data["cve"]
    
    # Extract basic information
    cve_id = cve["id"]
    published = cve.get("published", "Unknown")
    description = cve.get("descriptions", [{}])[0].get("value", "No description available") if cve.get("descriptions") else "No description available"
    
    # Extract metrics if available
    metrics = cve.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
    cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV2") else {}
    
    # Format the data
    formatted_data = f"""
CVE ID: {cve_id}
Published: {published}
Description: {description}

CVSS V3 Metrics:
Base Score: {cvss_v3.get('baseScore', 'N/A')}
Vector: {cvss_v3.get('vectorString', 'N/A')}
Attack Vector: {cvss_v3.get('attackVector', 'N/A')}
Attack Complexity: {cvss_v3.get('attackComplexity', 'N/A')}
Privileges Required: {cvss_v3.get('privilegesRequired', 'N/A')}
User Interaction: {cvss_v3.get('userInteraction', 'N/A')}
Scope: {cvss_v3.get('scope', 'N/A')}
Confidentiality Impact: {cvss_v3.get('confidentialityImpact', 'N/A')}
Integrity Impact: {cvss_v3.get('integrityImpact', 'N/A')}
Availability Impact: {cvss_v3.get('availabilityImpact', 'N/A')}

CVSS V2 Metrics:
Base Score: {cvss_v2.get('baseScore', 'N/A')}
Vector: {cvss_v2.get('vectorString', 'N/A')}
    """
    
    if "references" in cve:
        formatted_data += "\nReferences:\n"
        for ref in cve["references"]:
            formatted_data += f"- {ref.get('url', 'No URL')}\n"
    
    if "_sources" in cve_data:
        formatted_data += f"\nData Sources: {', '.join(cve_data['_sources'])}\n"
    
    if "_additional_sources" in cve_data and "GitHub" in cve_data["_additional_sources"]:
        github_data = cve_data["_additional_sources"]["GitHub"]
        if "cve" in github_data and "references" in github_data["cve"]:
            formatted_data += "\nGitHub Repositories:\n"
            for ref in github_data["cve"]["references"]:
                if "name" in ref and "url" in ref:
                    formatted_data += f"- {ref['name']}: {ref['url']}\n"
    
    if "_additional_sources" in cve_data and "CIRCL" in cve_data["_additional_sources"]:
        circl_data = cve_data["_additional_sources"]["CIRCL"]
        if "_source_data" in circl_data:
            source_data = circl_data["_source_data"]
            
            if "cwe" in source_data:
                formatted_data += f"\nCWE: {source_data['cwe']}\n"
            
            if "vulnerable_product" in source_data and source_data["vulnerable_product"]:
                formatted_data += "\nVulnerable Products:\n"
                for product in source_data["vulnerable_product"][:5]:  # Limit to first 5 products
                    formatted_data += f"- {product}\n"
    
    return formatted_data

def generate_cve_embedding(cve_data: Dict[Any, Any]) -> List[float]:
    """
    Generate an embedding vector for the CVE using OpenAI's embeddings API
    
    Args:
        cve_data: The CVE data from multiple sources
        
    Returns:
        List[float]: The embedding vector
    """
    # Get the CVE description and other relevant text
    cve = cve_data["cve"]
    texts = []
    
    # Extract description
    if "descriptions" in cve and cve["descriptions"]:
        for desc in cve["descriptions"]:
            if desc.get("lang") == "en":
                texts.append(desc.get("value", ""))
    
    # Extract vulnerability types and product names
    if "configurations" in cve_data:
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if cpe:
                        texts.append(cpe)
    
    # Add CWE information if available
    if "_additional_sources" in cve_data and "CIRCL" in cve_data["_additional_sources"]:
        circl_data = cve_data["_additional_sources"]["CIRCL"]
        if "_source_data" in circl_data and "cwe" in circl_data["_source_data"]:
            cwe = circl_data["_source_data"]["cwe"]
            if isinstance(cwe, str):
                texts.append(f"CWE: {cwe}")
            elif isinstance(cwe, list):
                texts.append(f"CWE: {', '.join(cwe)}")
    
    combined_text = " ".join(texts)
    
    if not combined_text:
        return []
    
    try:
        llm = OpenAIProvider()
        
        return llm.generate_embedding(combined_text)
    except Exception as e:
        print(f"Error generating embedding: {e}")
        return []

def generate_summary(cve_data: Dict[Any, Any]) -> str:
    """
    Generate a structured summary of the CVE using an LLM
    
    Args:
        cve_data: The CVE data from multiple sources
        
    Returns:
        str: Generated summary
    """
    formatted_cve = format_cve_for_prompt(cve_data)
    
    prompt = f"""
Analyze the following CVE information from multiple data sources and provide a comprehensive structured summary.
Include:
1. A brief one-sentence description of the vulnerability
2. Technical details of the vulnerability
3. Potential impact on affected systems
4. Severity assessment
5. Recommended mitigation steps
6. A summary of any additional information from multiple sources (if provided)

Here's the CVE information:
{formatted_cve}

Format your response in a clear, structured way with headers for each section.
"""
    
    try:
        llm = OpenAIProvider()
        return llm.generate_text(prompt)
    except Exception as e:
        return f"Error generating summary with LLM: {e}\n\nRaw CVE data: {formatted_cve}" 