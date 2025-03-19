import streamlit as st
import sys
import os
from utils.validator import validate_cve_id
from services.cve_service import fetch_cve_details
from services.llm_service import generate_summary
from database.db_manager import DBManager
import pandas as pd

# Configure Streamlit page settings
st.set_page_config(
    page_title="CVE Analysis Agent",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": None,
        "Report a bug": None,
        "About": None
    }
)

# Initialize session state variables
if "search_history" not in st.session_state:
    st.session_state.search_history = []
if "current_cve_id" not in st.session_state:
    st.session_state.current_cve_id = ""
if "current_page" not in st.session_state:
    st.session_state.current_page = 1
if "items_per_page" not in st.session_state:
    st.session_state.items_per_page = 6
if "show_loading" not in st.session_state:
    st.session_state.show_loading = False
if "error_message" not in st.session_state:
    st.session_state.error_message = None
if "success_message" not in st.session_state:
    st.session_state.success_message = None
if "info_message" not in st.session_state:
    st.session_state.info_message = None

def load_css():
    # Load custom CSS or use inline styles if file not found
    css_file = os.path.join(os.path.dirname(__file__), "static", "style.css")
    if os.path.exists(css_file):
        with open(css_file) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    else:
        st.markdown("""
<style>
        .main-header {font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem;}
        .subheading {font-size: 1.2rem; margin-bottom: 2rem; opacity: 0.8;}
        .section-header {font-size: 1.8rem; margin-top: 2rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid rgba(98, 0, 234, 0.5);}
        .result-box {background-color: white; border-radius: 12px; padding: 25px; margin: 16px 0; box-shadow: 0 5px 15px rgba(0,0,0,0.1); border-left: 5px solid #6200EA;}
        .card {background-color: white; border-radius: 12px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);}
        .error-box {background-color: rgba(207, 102, 121, 0.1); border-left: 4px solid #CF6679; padding: 10px 15px; border-radius: 4px; margin: 16px 0;}
        .success-box {background-color: rgba(3, 218, 198, 0.1); border-left: 4px solid #03DAC6; padding: 10px 15px; border-radius: 4px; margin: 16px 0;}
        .info-box {background-color: rgba(33, 150, 243, 0.1); border-left: 4px solid #2196F3; padding: 10px 15px; border-radius: 4px; margin: 16px 0;}
        /* Hide Streamlit menu button */
        .stDeployButton {display: none !important;}
        </style>
        """, unsafe_allow_html=True)

def handle_search(cve_id):
    # Process CVE ID search and update session state
    if not cve_id:
        st.session_state.error_message = "Please enter a CVE ID"
        return
    
    if not validate_cve_id(cve_id):
        st.session_state.error_message = "Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN"
        return
    
    st.session_state.current_cve_id = cve_id
    
    if cve_id not in st.session_state.search_history:
        st.session_state.search_history.insert(0, cve_id)
        if len(st.session_state.search_history) > 10:
            st.session_state.search_history = st.session_state.search_history[:10]
    
    st.session_state.error_message = None
    st.session_state.success_message = None
    st.session_state.info_message = None
    st.session_state.show_loading = True

def handle_similar_cve_click(cve_id):
    # Update session state when user clicks on a similar CVE
    st.session_state.current_cve_id = cve_id
    st.session_state.error_message = None
    st.session_state.success_message = None
    st.session_state.info_message = None
    st.session_state.show_loading = True

def change_page(page_num):
    # Update pagination for similar CVEs results
    st.session_state.current_page = page_num

def display_message_if_exists():
    """Display any status messages that exist in session state"""
    if st.session_state.error_message:
        st.markdown(f"<div class='error-box'>{st.session_state.error_message}</div>", unsafe_allow_html=True)
    
    if st.session_state.success_message:
        st.markdown(f"<div class='success-box'>{st.session_state.success_message}</div>", unsafe_allow_html=True)
    
    if st.session_state.info_message:
        st.markdown(f"<div class='info-box'>{st.session_state.info_message}</div>", unsafe_allow_html=True)

def main():
    load_css()
    
    st.markdown("<h1 class='main-header'>CVE Analysis Agent</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subheading'>Retrieve, analyze, and summarize Common Vulnerabilities and Exposures (CVEs) from multiple sources</p>", unsafe_allow_html=True)
    
    # Initialize database connection
    db = DBManager()
    
    # Search form for CVE ID input
    with st.form(key="search_form", clear_on_submit=False):
        cols = st.columns([4, 1])
        
        with cols[0]:
            cve_id = st.text_input(
                label="CVE ID",
                placeholder="Enter CVE ID (e.g., CVE-2021-44228)",
                help="Input a valid CVE ID in the format CVE-YYYY-NNNNN",
                label_visibility="collapsed"
            )
        
        with cols[1]:
            search_submitted = st.form_submit_button("Search", type="primary", use_container_width=True)
    
    if search_submitted:
        handle_search(cve_id)
    
    # Handle URL query parameters
    query_params = st.query_params
    if "cve_id" in query_params and not st.session_state.current_cve_id:
        param_cve_id = query_params["cve_id"]
        handle_search(param_cve_id)
        st.query_params.clear()
    
    display_message_if_exists()
    
    # Display search history in sidebar
    if st.session_state.search_history:
        st.sidebar.markdown("""
        <div style="padding: 10px 0; margin-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.1);">
            <h3 style="color: white; font-size: 1.2rem; margin: 0; font-weight: 500;">Recent Searches</h3>
        </div>
        """, unsafe_allow_html=True)
        
        for hist_cve in st.session_state.search_history:
            if st.sidebar.button(hist_cve, key=f"history_{hist_cve}", use_container_width=True):
                handle_search(hist_cve)
    
    # Process and display CVE data if a search has been performed
    if st.session_state.current_cve_id:
        cve_id = st.session_state.current_cve_id
        
        if st.session_state.show_loading:
            with st.container():
                with st.spinner(f"Retrieving and analyzing {cve_id}..."):
                    try:
                        # Try to fetch CVE from database first, then external sources if needed
                        stored_cve = db.get_cve(cve_id)
                        if stored_cve:
                            st.session_state.success_message = f"Found {cve_id} in database."
                            cve_data = stored_cve
                        else:
                            st.session_state.info_message = f"Retrieving {cve_id} from multiple sources..."
                            try:
                                cve_data = fetch_cve_details(cve_id)
                                db.store_cve(cve_id, cve_data)
                                st.session_state.success_message = f"Successfully retrieved and stored {cve_id}"
                                st.session_state.info_message = None
                            except Exception as e:
                                st.session_state.error_message = f"Error retrieving CVE details: {str(e)}"
                                st.session_state.show_loading = False
                                st.rerun()
                        
                        # Generate and display AI summary of the vulnerability
                        try:
                            summary = generate_summary(cve_data)
                            clean_summary = summary.strip()
                            
                            st.markdown("<h2 class='section-header'>Vulnerability Summary</h2>", unsafe_allow_html=True)
                            
                            st.markdown(f"""
                            <div class='result-box'>
                                <div style='font-size: 1rem;'>
                                    {clean_summary}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                        except Exception as e:
                            st.markdown("<h2 class='section-header'>Vulnerability Summary</h2>", unsafe_allow_html=True)
                            st.markdown(f"<div class='error-box'>Error generating summary: {str(e)}</div>", unsafe_allow_html=True)
                            st.markdown("<div class='info-box'>Please set a valid OpenAI API key as an environment variable (OPENAI_API_KEY) to generate summaries using GPT-4o.</div>", unsafe_allow_html=True)
                        
                        st.markdown("<hr>", unsafe_allow_html=True)
                        
                        # Display data sources section
                        st.markdown("<h2 class='section-header'>Data Sources</h2>", unsafe_allow_html=True)
                        
                        has_sources = "_sources" in cve_data
                        has_additional = "_additional_sources" in cve_data
                        
                        if has_sources or has_additional:
                            sources_col1, sources_col2 = st.columns([1, 1])
                            
                            with sources_col1:
                                if has_sources:
                                    sources_html = "<div style='margin-top: 10px;'>"
                                    for source in cve_data["_sources"]:
                                        sources_html += f"<span class='source-tag'>{source}</span>"
                                    sources_html += "</div>"
                                    st.markdown(sources_html, unsafe_allow_html=True)
                            
                            with sources_col2:
                                if has_additional:
                                    for source, data in cve_data["_additional_sources"].items():
                                        with st.expander(f"{source} Information"):
                                            if source == "GitHub" and "_source_data" in data and "repos" in data["_source_data"]:
                                                st.markdown("#### GitHub Repositories")
                                                for repo in data["_source_data"]["repos"]:
                                                    st.markdown(f"[{repo['full_name']}]({repo['html_url']})")
                                            elif source == "CIRCL" and "_source_data" in data:
                                                source_data = data["_source_data"]
                                                if "cwe" in source_data:
                                                    st.markdown(f"**CWE:** {source_data['cwe']}")
                                                if "vulnerable_product" in source_data and source_data["vulnerable_product"]:
                                                    st.markdown("**Vulnerable Products:**")
                                                    for product in source_data["vulnerable_product"][:10]:
                                                        st.markdown(f"- {product}")
                        else:
                            st.markdown("<div class='info-box'>No source information available</div>", unsafe_allow_html=True)
                        
                        st.markdown("<hr>", unsafe_allow_html=True)
                        
                        # Display similar vulnerabilities section
                        st.markdown("<h2 class='section-header'>Similar Vulnerabilities</h2>", unsafe_allow_html=True)
                        
                        similar_cves = db.find_similar_cves(cve_id)
                                
                        if similar_cves:
                            # Setup pagination for similar CVEs
                            total_pages = (len(similar_cves) + st.session_state.items_per_page - 1) // st.session_state.items_per_page
                            
                            start_idx = (st.session_state.current_page - 1) * st.session_state.items_per_page
                            end_idx = min(start_idx + st.session_state.items_per_page, len(similar_cves))
                            
                            current_page_cves = similar_cves[start_idx:end_idx]
                            
                            table_data = []
                            
                            # Extract data for similar CVEs table
                            for cve_info in current_page_cves:
                                cve = cve_info["cve_id"]
                                similarity = cve_info["similarity"]
                                
                                similar_cve_data = db.get_cve(cve)
                                if similar_cve_data:
                                    severity = "Unknown"
                                    severity_text = "Unknown"
                                    description = "No description available"
                                    
                                    if "cve" in similar_cve_data:
                                        similar_cve = similar_cve_data["cve"]
                                        
                                        if "descriptions" in similar_cve and similar_cve["descriptions"]:
                                            for desc in similar_cve["descriptions"]:
                                                if desc.get("lang") == "en":
                                                    description = desc.get("value", "")
                                                    break
                                        
                                        # Extract severity information from CVSS metrics
                                        metrics = similar_cve.get("metrics", {})
                                        
                                        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                                            severity_text = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "Unknown")
                                        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                                            score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)
                                            if score >= 7.0:
                                                severity_text = "HIGH"
                                            elif score >= 4.0:
                                                severity_text = "MEDIUM"
                                            else:
                                                severity_text = "LOW"
                                    
                                    short_description = description[:150] + "..." if len(description) > 150 else description
                                    
                                    table_data.append({
                                        "CVE ID": cve,
                                        "Similarity": f"{similarity:.1f}%",
                                        "Severity": severity_text,
                                        "Description": short_description,
                                        "Action": cve
                                    })
                            
                            df = pd.DataFrame(table_data)
                            
                            # Apply table styling
                            st.markdown("""
                            <style>
                            .dataframe {
                                width: 100%;
                                border-collapse: collapse;
                            }
                            .dataframe th {
                                background-color: #121212;
                                color: white;
                                padding: 12px;
                                text-align: left;
                                border-bottom: 2px solid #444;
                            }
                            .dataframe td {
                                padding: 10px 12px;
                                border-bottom: 1px solid #333;
                            }
                            .dataframe tr:hover {
                                background-color: rgba(98, 0, 234, 0.05);
                            }
                            .similarity-high {
                                color: #03DAC6;
                                font-weight: bold;
                            }
                            .similarity-medium {
                                color: #FFB74D;
                                font-weight: bold;
                            }
                            .similarity-low {
                                color: #BBBBBB;
                                font-weight: normal;
                            }
                            .severity-cell-CRITICAL {
                                color: #CF6679;
                                font-weight: bold;
                            }
                            .severity-cell-HIGH {
                                color: #FF5722;
                                font-weight: bold;
                            }
                            .severity-cell-MEDIUM {
                                color: #FFB74D;
                                font-weight: bold;
                            }
                            .severity-cell-LOW {
                                color: #03DAC6;
                                font-weight: bold;
                            }
                            </style>
                            """, unsafe_allow_html=True)
                            
                            # Create custom table header
                            columns = st.columns([3, 2, 2, 6, 2])
                            
                            columns[0].markdown("<b>CVE ID</b>", unsafe_allow_html=True)
                            columns[1].markdown("<b>Similarity</b>", unsafe_allow_html=True)
                            columns[2].markdown("<b>Severity</b>", unsafe_allow_html=True)
                            columns[3].markdown("<b>Description</b>", unsafe_allow_html=True)
                            columns[4].markdown("<b>Action</b>", unsafe_allow_html=True)
                            
                            # Display table rows with styling
                            for _, row in df.iterrows():
                                cols = st.columns([3, 2, 2, 6, 2])
                                
                                cols[0].markdown(f"{row['CVE ID']}")
                                
                                similarity_value = float(row['Similarity'].strip('%'))
                                similarity_class = "similarity-high" if similarity_value >= 70 else ("similarity-medium" if similarity_value >= 40 else "similarity-low")
                                cols[1].markdown(f"<span class='{similarity_class}'>{row['Similarity']}</span>", unsafe_allow_html=True)
                                
                                severity_class = f"severity-cell-{row['Severity']}"
                                cols[2].markdown(f"<span class='{severity_class}'>{row['Severity']}</span>", unsafe_allow_html=True)
                                
                                cols[3].markdown(f"{row['Description']}")
                                
                                cve_id_for_button = row['Action']
                                if cols[4].button("Analyze", key=f"analyze_{cve_id_for_button}"):
                                    handle_similar_cve_click(cve_id_for_button)
                                    st.rerun()
                            
                            # Display pagination controls if needed
                            if total_pages > 1:
                                pagination_cols = st.columns([1, 3, 1])
                                with pagination_cols[1]:
                                    col1, col2, col3 = st.columns([1, 1, 1])
                                    
                                    with col1:
                                        if st.session_state.current_page > 1:
                                            if st.button("← Previous", key="prev_page"):
                                                change_page(st.session_state.current_page - 1)
                                                st.rerun()
                                    
                                    with col2:
                                        st.markdown(f"<div style='text-align: center; padding: 10px;'>Page {st.session_state.current_page} of {total_pages}</div>", unsafe_allow_html=True)
                                    
                                    with col3:
                                        if st.session_state.current_page < total_pages:
                                            if st.button("Next →", key="next_page"):
                                                change_page(st.session_state.current_page + 1)
                                                st.rerun()
                        else:
                            st.markdown("<div class='info-box'>No similar CVEs found</div>", unsafe_allow_html=True)
                        
                        st.session_state.show_loading = False
                    
                    except Exception as e:
                        st.session_state.error_message = f"An error occurred: {str(e)}"
                        st.session_state.show_loading = False
                        st.rerun()

if __name__ == "__main__":
    main()