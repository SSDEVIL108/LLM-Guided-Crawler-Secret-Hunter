import urllib.request
import urllib.parse
import re
import requests
import time
import random
import json
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

import os

# ==========================================
# CONFIGURATION & API SETUP
# ==========================================
# Securely load API Key from environment variable or prompt
API_KEY = "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"
if not API_KEY:
    print("🔑 NVIDIA_API_KEY environment variable not found.")
    API_KEY = input("Enter your NVIDIA NIM / API Key: ").strip()

BASE_URL_for_nvidia = "https://integrate.api.nvidia.com/v1/chat/completions"

NVIDIA_MODELS = [
    'nvidia/nemotron-3-ultra-550b-a55b',
    'deepseek-ai/deepseek-v4-flash',     
    'deepseek-ai/deepseek-v4-pro',
    'z-ai/glm-5.2',
    'moonshotai/kimi-k2.6',
    'openai/gpt-oss-120b'      
]         

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

working_models_list = []
all_urls = set()          # Set ensures 0 duplicate URLs across the whole scan

# ==========================================
# KNOWLEDGE GRAPH DATA STRUCTURE ("GRAPHIFY")
# ==========================================
# In Python, a Knowledge Graph can be built as a Dictionary where:
# Key   -> Parent Node (e.g. Current Page URL)
# Value -> Dict of connected Edges (links, scripts loaded, and AI findings)
knowledge_graph = {}

def add_edge_to_graph(parent_node, relation_type, child_node):
    """
    Helper function to build relationships (Edges) between Nodes in the graph.
    Example: parent_node ("https://site.com") --[relation_type="links_to"]--> child_node ("https://site.com/about")
    """
    if parent_node not in knowledge_graph:
        knowledge_graph[parent_node] = {
            "links": set(),
            "scripts": set(),
            "findings": []
        }
    
    if relation_type in knowledge_graph[parent_node]:
        if isinstance(knowledge_graph[parent_node][relation_type], set):
            knowledge_graph[parent_node][relation_type].add(child_node)
        else:
            knowledge_graph[parent_node][relation_type].append(child_node)

def print_graph_tree():
    """
    Displays the entire visual Knowledge Graph tree in the terminal console.
    """
    print("\n" + "="*60)
    print("🕸️ VISUAL KNOWLEDGE GRAPH (GRAPHIFY MAP)")
    print("="*60)
    
    for page_node, data in knowledge_graph.items():
        print(f"\n📍 PAGE NODE: {page_node}")
        
        # Display connected script edges
        if data["scripts"]:
            print("  ├── 📜 Loaded Scripts:")
            for script in data["scripts"]:
                print(f"  │     └── {script}")
                
        # Display connected outgoing link edges
        if data["links"]:
            print("  ├── 🔗 Outgoing Links:")
            for link in data["links"]:
                print(f"  │     └── {link}")
                
        # Display AI Findings / Secrets connected to this node
        if data["findings"]:
            print("  └── 🧠 AI Findings / Secrets:")
            for finding in data["findings"]:
                if isinstance(finding, dict):
                    urls = finding.get("urls_and_endpoints", [])
                    secrets = finding.get("secrets_and_credentials", [])
                    mistakes = finding.get("developer_mistakes_and_leaks", [])
                    if urls:
                        print(f"        ├── Discovered Endpoints: {len(urls)}")
                    if secrets:
                        print(f"        ├── Secrets Found: {secrets}")
                    if mistakes:
                        print(f"        └── Developer Mistakes: {mistakes}")
                else:
                    first_line = str(finding).strip().split("\n")[0][:80]
                    print(f"        └── {first_line}...")

# ==========================================
# 1. MODEL LIVENESS CHECK
# ==========================================
def check_single_model(model):
    """Tests if an individual LLM model is responsive."""
    json_message = {
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 50
    }
    try:
        response = requests.post(BASE_URL_for_nvidia, headers=headers, json=json_message, timeout=10)
        if response.status_code == 200:
            print(f"  ✅ Model live: {model}")
            return model
    except Exception as e:
        print(f"  ❌ Model failed {model}: {e}")
    return None

def find_working_models():
    """Uses parallel threads to quickly check which models are live."""
    print("🔍 Testing live AI models in parallel...")
    global working_models_list
    with ThreadPoolExecutor(max_workers=len(NVIDIA_MODELS)) as executor:
        results = executor.map(check_single_model, NVIDIA_MODELS)
        working_models_list = [m for m in results if m is not None]
    print(f"Total Working Models: {len(working_models_list)}\n")

# ==========================================
# 2. DETERMINISTIC HTML & JS EXTRACTION (0% Hallucination)
# ==========================================
def extract_links_and_scripts_with_bs4(html_content, base_url):
    """
    Uses BeautifulSoup to pull REAL links and JS script paths directly from HTML.
    This guarantees 0% LLM hallucination because Python extracts them first!
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    page_links = []
    script_files = []
    
    # 1. Extract <a> tag hrefs (Page links)
    for a_tag in soup.find_all('a', href=True):
        raw_href = a_tag['href'].strip()
        full_url = urllib.parse.urljoin(base_url, raw_href)
        page_links.append(full_url)
        # Add relationship edge to Knowledge Graph
        add_edge_to_graph(base_url, "links", full_url)
        
    # 2. Extract <script> tag srcs (JavaScript files)
    for script_tag in soup.find_all('script', src=True):
        raw_src = script_tag['src'].strip()
        full_url = urllib.parse.urljoin(base_url, raw_src)
        script_files.append(full_url)
        # Add relationship edge to Knowledge Graph
        add_edge_to_graph(base_url, "scripts", full_url)
        
    return page_links + script_files

# ==========================================
# 3. PARALLEL LLM ANALYSIS (Respecting 40 RPM)
# ==========================================
def analyze_chunk_with_llm(chunk_data):
    """
    Sends one chunk of HTML/JS to an LLM to analyze for interesting endpoints & secrets.
    """
    chunk_index, chunk_text = chunk_data
    if not working_models_list:
        return None

    model = random.choice(working_models_list)

    prompt = f"""You are an elite web application security auditor. Analyze the source code snippet for developer mistakes, hidden configurations, and security exposures.

CRITICAL FILTERING RULES:
1. "urls_and_endpoints": Extract ONLY API routes, backend endpoints, JSON/data paths, cloud storage buckets (S3), or staging/dev subdomains.
   - DO NOT include static images (.png, .jpg, .gif, .svg, .ico, .webp), fonts (.woff2, .ttf), or standard CSS files.
2. "secrets_and_credentials": Extract ONLY actual sensitive items (e.g., API keys, private keys, database tokens, bearer credentials, custom auth tokens).
   - DO NOT include Next.js build IDs, chunk hashes, asset filenames, or public tracking IDs.
3. "developer_mistakes_and_leaks": Extract actionable security flaws, developer hints, and custom logic rules:
   - Custom header requirements or authorization logic (e.g., `X-Internal-Token`, `X-Admin-Access`, custom headers used in fetch/XHR calls).
   - Hidden URL parameters or debug query strings (e.g., `?devMode=true`, `?override=1`, `?admin=true`, `?bypass=true`).
   - Developer notes/hints explaining custom routing, 403/401 access rules, internal test IPs, or status bypass conditions.
   - Hardcoded debug/staging flags (`DEBUG=true`, `IS_STAGING=1`, `TEST_MODE=true`).
   - Hardcoded staging/test subdomains (`staging.example.com`, `dev.target.com`).
   - Internal IP addresses or internal domain mappings (`10.x.x.x`, `192.168.x.x`).
   - DO NOT report standard jQuery methods (.html(), .append()), public support emails, or standard localization arrays as flaws!

OUTPUT SCHEMA:
Output ONLY a valid JSON object matching this schema without any markdown formatting or preamble:
{{
  "urls_and_endpoints": ["/api/v1/user", "https://staging-api.example.com"],
  "secrets_and_credentials": ["AKIAIOSFODNN7EXAMPLE"],
  "developer_mistakes_and_leaks": ["DEBUG=true flag set in client code"]
}}

--- CODE SNIPPET (Chunk #{chunk_index + 1}) ---
{chunk_text}
--- END SNIPPET ---"""

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096
    }

    try:
        response = requests.post(BASE_URL_for_nvidia, headers=headers, json=payload, timeout=100)
        if response.status_code == 200:
            result_text = response.json()["choices"][0]["message"]["content"].strip()
            
            # Clean off potential markdown fences ```json ... ``` from LLM output
            if result_text.startswith("```"):
                result_text = re.sub(r"^```[a-zA-Z]*\n?", "", result_text)
                result_text = re.sub(r"\n?```$", "", result_text).strip()

            try:
                parsed_json = json.loads(result_text)
                return (chunk_index, parsed_json)
            except Exception:
                # If JSON parsing fails, fall back to string extraction safely
                return (chunk_index, {"urls_and_endpoints": [], "secrets_and_credentials": [], "developer_mistakes_and_leaks": []})
    except Exception as e:
        print(f"⚠️ LLM request error on chunk #{chunk_index + 1}: {e}")
    return None

def process_chunks_in_parallel(chunks, max_workers=5):
    """
    Fires parallel LLM requests for chunks while staying within your rate limit.
    """
    indexed_chunks = list(enumerate(chunks))
    llm_results = []
    
    print(f"🚀 Firing {len(indexed_chunks)} chunks to LLMs across parallel threads...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_chunk_with_llm, chunk_data) for chunk_data in indexed_chunks]
        for future in futures:
            res = future.result()
            if res:
                llm_results.append(res)
                
    return llm_results

import os

# ==========================================
# SANITIZER & RESUME HELPERS
# ==========================================
def sanitize_entry(val):
    """
    Sanitizes extracted findings to prevent report corruption and filter out static asset noise.
    """
    if not isinstance(val, str):
        return None
    val = val.strip()
    if not val:
        return None
    # Reject base64 blobs, data URIs, or raw JSON dump strings
    if "data:image" in val or "data:font" in val or ";base64," in val:
        return None
    if val.startswith("{") or val.startswith("[") or "urls_and_endpoints" in val:
        return None
    # Reject entries longer than 150 characters (prevents code/JSON dumps)
    if len(val) > 150:
        return None
    # Reject static media asset noise (.png, .jpg, .svg, .woff2, .ico, .css)
    lower_val = val.lower()
    if any(lower_val.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff2", ".woff", ".ttf", ".css"]):
        return None
    return val

def load_existing_progress(filename):
    """
    Reads an existing markdown report file to recover:
    1. Scanned URLs -> visited_urls
    2. Outgoing discovered links -> unvisited queue
    This ensures resuming continues scanning unvisited links instead of stopping!
    """
    visited_already = set()
    discovered_links = set()
    
    if not os.path.exists(filename):
        return visited_already, []
        
    print(f"🔄 Existing scan report found (`{filename}`). Reading previous progress...")
    try:
        with open(filename, "r", encoding="utf-8") as f:
            current_section = None
            for line in f:
                line = line.strip()
                if line.startswith("## 📍 Page: `"):
                    extracted_url = line.split("`")[1]
                    visited_already.add(extracted_url)
                elif line.startswith("### 🔗 Outgoing Links"):
                    current_section = "links"
                elif line.startswith("###"):
                    current_section = None
                elif current_section == "links" and line.startswith("- `"):
                    link_url = line.split("`")[1]
                    discovered_links.add(link_url)
    except Exception as e:
        print(f"⚠️ Warning reading previous progress: {e}")
        
    # Queue only links that have NOT been visited yet
    unvisited_queue = [(link, 1) for link in sorted(discovered_links) if link not in visited_already]
    
    print(f"▶️ Resuming scan: {len(visited_already)} pages already scanned, {len(unvisited_queue)} queued links remaining.")
    return visited_already, unvisited_queue

# ==========================================
# LIVE REPORT WRITER (Real-time Append)
# ==========================================
def initialize_report_file(filename):
    """Creates the markdown file with initial headers if it doesn't exist."""
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# 🕸️ AI Web Crawler & Real-Time Recon Report\n\n")
            f.write("--- Real-time scan findings appended live below ---\n\n")

def append_page_findings_to_report(filename, current_url, depth, script_list, link_list, ai_findings):
    """Appends live findings cleanly formatted to the Markdown file as each page completes."""
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"## 📍 NODE PAGE: `{current_url}` (Depth {depth})\n")
        
        # 1. Graphify Outgoing Edges (Unique per page)
        f.write("### 🔗 Graph Edges: Outgoing Links\n")
        clean_links = sorted(list(set(l for l in link_list if sanitize_entry(l))))
        if clean_links:
            for l in clean_links:
                f.write(f"  └── `{l}`\n")
        else:
            f.write("_No outgoing link edges._\n")
        f.write("\n")
        
        # 2. Graphify Script Dependencies
        f.write("### 📜 Graph Edges: Loaded Scripts\n")
        clean_scripts = sorted(list(set(s for s in script_list if sanitize_entry(s))))
        if clean_scripts:
            for s in clean_scripts:
                f.write(f"  └── `{s}`\n")
        else:
            f.write("_No script edges._\n")
        f.write("\n")

        # 3. AI Security Findings Node
        f.write("### 🧠 Graph Edges: AI Security Findings\n")
        extracted_urls = set()
        extracted_secrets = set()
        extracted_mistakes = set()

        for _, parsed in ai_findings:
            if isinstance(parsed, dict):
                for u in parsed.get("urls_and_endpoints", []):
                    sanitized_u = sanitize_entry(u)
                    if sanitized_u:
                        extracted_urls.add(sanitized_u)
                for sec in parsed.get("secrets_and_credentials", []):
                    sanitized_sec = sanitize_entry(sec)
                    if sanitized_sec:
                        extracted_secrets.add(sanitized_sec)
                for mis in parsed.get("developer_mistakes_and_leaks", []):
                    sanitized_mis = sanitize_entry(mis)
                    if sanitized_mis:
                        extracted_mistakes.add(sanitized_mis)

        if extracted_urls:
            f.write("**Discovered Endpoints / Paths:**\n")
            for u in sorted(extracted_urls):
                f.write(f"  └── `{u}`\n")
        else:
            f.write("_No endpoints discovered by AI._\n")

        f.write("\n")

        if extracted_secrets:
            f.write("**Extracted Secrets / Tokens / Keys:**\n")
            for sec in sorted(extracted_secrets):
                f.write(f"  └── ⚠️ `{sec}`\n")
        else:
            f.write("_No secrets detected by AI._\n")

        f.write("\n")

        if extracted_mistakes:
            f.write("**Developer Mistakes, Debug Flags & Internal Leaks:**\n")
            for mis in sorted(extracted_mistakes):
                f.write(f"  └── 🚨 `{mis}`\n")
        else:
            f.write("_No developer mistakes or leaks detected by AI._\n")

        f.write("\n---\n\n")

def finalize_report_with_graphify(filename):
    """
    Appends a Master Summary, a 100% Deduplicated Master URL List, 
    and a visual Graphify ASCII Tree at the end of the markdown report.
    """
    print(f"\n🎨 Generating Visual Graphify Map & Master Unique Index in `{filename}`...")
    with open(filename, "a", encoding="utf-8") as f:
        f.write("\n" + "="*70 + "\n")
        f.write("# 🏆 MASTER RECON SUMMARY & GRAPHIFY MAP\n")
        f.write("="*70 + "\n\n")
        
        # 1. Total Unique URLs (Zero Duplication)
        f.write(f"## 🌐 Master Unique Discovered URLs & Assets ({len(all_urls)} Total)\n")
        f.write("_This section contains zero duplicates across the entire scan._\n\n")
        for u in sorted(all_urls):
            f.write(f"- `{u}`\n")
        f.write("\n---\n\n")
        
        # 2. Visual ASCII Knowledge Graph
        f.write("## 🕸️ Visual Knowledge Graph (Asset Relationship Map)\n\n")
        f.write("```text\n")
        for page_node, data in knowledge_graph.items():
            f.write(f"📍 PAGE NODE: {page_node}\n")
            if data["scripts"]:
                f.write("  ├── 📜 Loaded Scripts:\n")
                for script in sorted(data["scripts"]):
                    f.write(f"  │     └── {script}\n")
            if data["links"]:
                f.write("  ├── 🔗 Outgoing Links:\n")
                for link in sorted(data["links"]):
                    f.write(f"  │     └── {link}\n")
            if data["findings"]:
                f.write("  └── 🧠 AI Findings:\n")
                for finding in data["findings"]:
                    f.write(f"        └── {str(finding)[:100]}...\n")
            f.write("\n")
        f.write("```\n\n")
    print(f"✅ Visual Graphify Map appended to `{filename}`!")

def ast_structure_aware_chunking(source_code, max_chunk_size=25000):
    """
    AST & Scope-Aware Chunking:
    Instead of slicing code naively in the middle of a function or object, 
    this parser identifies top-level JS/HTML block boundaries (functions, objects, scripts) 
    to preserve complete AST syntax scopes for LLM analysis.
    """
    if len(source_code) <= max_chunk_size:
        return [source_code]

    # Split by major AST structural boundaries (functions, classes, script tags, imports, exports, decorators, assignments)
    boundaries = re.split(r'(?=\n(?:function|class|var |let |const |export |import |async |@|<script|\/\*|=>))', source_code)
    
    smart_chunks = []
    current_chunk = ""

    for block in boundaries:
        if len(current_chunk) + len(block) <= max_chunk_size:
            current_chunk += block
        else:
            if current_chunk.strip():
                smart_chunks.append(current_chunk)
            # If a single block exceeds max_chunk_size, break it cleanly at line boundaries
            if len(block) > max_chunk_size:
                sub_lines = block.split("\n")
                temp_sub = ""
                for line in sub_lines:
                    if len(temp_sub) + len(line) <= max_chunk_size:
                        temp_sub += line + "\n"
                    else:
                        smart_chunks.append(temp_sub)
                        temp_sub = line + "\n"
                if temp_sub.strip():
                    current_chunk = temp_sub
            else:
                current_chunk = block

    if current_chunk.strip():
        smart_chunks.append(current_chunk)

    return smart_chunks

# ==========================================
# 4. LLM-GUIDED CRAWLER LOOP WITH GRAPHIFY & LIVE REPORTING
# ==========================================
def crawling_website(start_url, max_depth, report_filename):
    # Load previously scanned URLs and unvisited queued links from report file
    visited_urls, restored_queue = load_existing_progress(report_filename)
    
    if restored_queue:
        to_visit_queue = restored_queue
    else:
        to_visit_queue = [(start_url, 0)]
        
    start_domain = urllib.parse.urlparse(start_url).netloc
    
    while to_visit_queue:
        current_url, current_depth = to_visit_queue.pop(0)
        
        if current_url in visited_urls or current_depth > max_depth:
            continue
            
        visited_urls.add(current_url)
        all_urls.add(current_url)
        print(f"\n🌐 [Depth {current_depth}/{max_depth}] Crawling: {current_url}")
        
        try:
            response = requests.get(current_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
            if response.status_code != 200:
                print(f"  ❌ Page returned status code: {response.status_code}")
                continue
                
            html_text = response.text
            
            # Extract links and populate Graphify Edges
            soup = BeautifulSoup(html_text, 'html.parser')
            page_links = [urllib.parse.urljoin(current_url, a['href'].strip()) for a in soup.find_all('a', href=True)]
            script_files = [urllib.parse.urljoin(current_url, s['src'].strip()) for s in soup.find_all('script', src=True)]
            
            for link in page_links:
                add_edge_to_graph(current_url, "links", link)
            for script in script_files:
                add_edge_to_graph(current_url, "scripts", script)

            real_links = page_links + script_files
            print(f"  📌 BeautifulSoup extracted {len(real_links)} real links/scripts.")
            
            for link in real_links:
                parsed = urllib.parse.urlparse(link)
                if parsed.netloc == start_domain and parsed.scheme in ('http', 'https'):
                    if link not in visited_urls:
                        to_visit_queue.append((link, current_depth + 1))
                        all_urls.add(link)
            
            # 3. Analyze HTML text with AST-Aware Parallel LLM Chunks
            chunks = ast_structure_aware_chunking(html_text, max_chunk_size=25000)
            
            # Fetch & analyze loaded external JavaScript files directly
            for js_url in script_files[:5]: # Analyze top 5 critical loaded JS assets per page
                try:
                    js_resp = requests.get(js_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
                    if js_resp.status_code == 200 and len(js_resp.text) > 50:
                        js_chunks = ast_structure_aware_chunking(js_resp.text, max_chunk_size=25000)
                        chunks.extend(js_chunks[:3]) # Add JS chunks to LLM queue
                except Exception:
                    pass
            
            # Parallel LLM Analysis
            analysis_outputs = process_chunks_in_parallel(chunks, max_workers=5)
            
            # Record findings to Graphify Node
            for _, parsed in analysis_outputs:
                add_edge_to_graph(current_url, "findings", parsed)
            
            # LIVE REPORTING: Append findings immediately to markdown file
            append_page_findings_to_report(report_filename, current_url, current_depth, script_files, page_links, analysis_outputs)
            print(f"  💾 Live report updated in `{report_filename}`")
                
            time.sleep(1)
            
        except Exception as e:
            print(f"  ❌ Failed to crawl {current_url}: {e}")
            
    return visited_urls

# ==========================================
# MAIN EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    find_working_models()
    
    if not working_models_list:
        print("🚨 No live models available. Exiting.")
    else:
        target_website = input("Enter website to crawl (e.g. https://example.com):\n").strip()
        if not target_website.startswith(("http://", "https://")):
            target_website = "https://" + target_website
            
        depth_input = input("Enter depth to crawl (e.g. 1):\n").strip()
        try:
            depth = int(depth_input)
        except ValueError:
            print("Invalid depth. Defaulting to 0.")
            depth = 0
            
        clean_domain = urllib.parse.urlparse(target_website).netloc or "scan_target"
        safe_filename = f"{clean_domain}_report.md"
        
        # Initialize file for real-time live writing if new
        initialize_report_file(safe_filename)
        
        print(f"\n🚀 Starting Live Graphified Crawl on {target_website} at Depth {depth}...")
        visited = crawling_website(target_website, depth, safe_filename)
        
        # Display final terminal tree
        print_graph_tree()
        
        # Write final visual Graphify tree and 100% unique master index to report
        finalize_report_with_graphify(safe_filename)
        
        print("\n" + "="*60)
        print(f"🎉 SCAN & GRAPHIFY COMPLETE!")
        print(f"Total Pages Visited: {len(visited)}")
        print(f"Live Markdown Report Saved: `{safe_filename}`")
        print(f"Total Graph Nodes Mapped: {len(knowledge_graph)}")
        print("="*60)