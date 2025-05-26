#!/usr/bin/env python3
"""
Combined STIG Download and Parser
Downloads RHEL 8 and 9 STIGs from DoD Cyber Exchange and parses them into structured control data
"""

import requests
import zipfile
import os
import json
import xmltodict
import re

# Define direct URLs for RHEL 8 and RHEL 9 STIGs
RHEL8_STIG_URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R3_STIG.zip"
RHEL9_STIG_URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R4_STIG.zip"

DOWNLOAD_DIR = "stig_downloads"
EXTRACT_DIR = "stig_extracted"
OUTPUT_JSON_FILE = "rhel_stigs_parsed.json"
RAW_JSON_FILE = "rhel_stigs_raw.json"  # Optional: keep raw data too

def download_file(url, download_path):
    """Downloads a file from a given URL."""
    print(f"Attempting to download from: {url}")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(download_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Downloaded: {download_path}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")
        print("Please ensure you have network access to dl.dod.cyber.mil and that")
        print("your environment can handle any potential PKI/CAC authentication required.")
        return False

def unzip_file(zip_path, extract_to_dir):
    """Unzips a ZIP file to a specified directory."""
    print(f"Unzipping {zip_path} to {extract_to_dir}")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to_dir)
        print(f"Successfully unzipped {zip_path}")
        return True
    except zipfile.BadZipFile:
        print(f"Error: {zip_path} is not a valid ZIP file or is corrupted.")
        return False
    except Exception as e:
        print(f"Error unzipping {zip_path}: {e}")
        return False

def xml_to_json(xml_file_path):
    """Converts an XML file to a Python dictionary (JSON compatible)."""
    try:
        with open(xml_file_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()
        return xmltodict.parse(xml_content)
    except Exception as e:
        print(f"Error converting XML {xml_file_path} to JSON: {e}")
        return None

def extract_controls_from_benchmark(benchmark, rhel_version):
    """Extract STIG controls from Benchmark structure"""
    controls = {}

    # Look for Group elements (contain Rule elements)
    groups = []

    # Handle different possible structures
    if 'Group' in benchmark:
        group_data = benchmark['Group']
        if isinstance(group_data, list):
            groups = group_data
        elif isinstance(group_data, dict):
            groups = [group_data]

    # Also check for direct Rule elements
    rules = []
    if 'Rule' in benchmark:
        rule_data = benchmark['Rule']
        if isinstance(rule_data, list):
            rules = rule_data
        elif isinstance(rule_data, dict):
            rules = [rule_data]

    # Process Groups to find Rules
    for group in groups:
        if isinstance(group, dict):
            # Extract rules from group
            if 'Rule' in group:
                group_rules = group['Rule']
                if isinstance(group_rules, list):
                    rules.extend(group_rules)
                elif isinstance(group_rules, dict):
                    rules.append(group_rules)

    # Process each Rule to create control entries
    for rule in rules:
        if isinstance(rule, dict):
            control = extract_control_from_rule(rule, rhel_version)
            if control and 'id' in control:
                controls[control['id']] = control

    return controls

def extract_control_from_rule(rule, rhel_version):
    """Extract control information from a Rule element"""
    control = {}

    # Extract rule ID
    rule_id = rule.get('@id', '')
    if rule_id:
        control['id'] = rule_id
        control['rule_id'] = rule_id

    # Extract title
    title = rule.get('title', '')
    if isinstance(title, dict):
        title = title.get('#text', str(title))
    control['title'] = str(title)

    # Extract description
    description = rule.get('description', '')
    if isinstance(description, dict):
        description = description.get('#text', str(description))
    control['description'] = str(description)

    # Extract severity
    severity = rule.get('@severity', 'medium')
    control['severity'] = severity

    # Extract check content
    check_content = ''
    if 'check' in rule:
        check = rule['check']
        if isinstance(check, dict):
            if 'check-content' in check:
                check_content = check['check-content']
                if isinstance(check_content, dict):
                    check_content = check_content.get('#text', str(check_content))
        elif isinstance(check, list):
            for check_item in check:
                if isinstance(check_item, dict) and 'check-content' in check_item:
                    content = check_item['check-content']
                    if isinstance(content, dict):
                        content = content.get('#text', str(content))
                    check_content += str(content) + ' '

    control['check'] = str(check_content).strip()

    # Extract fix content
    fix_content = ''
    if 'fixtext' in rule:
        fixtext = rule['fixtext']
        if isinstance(fixtext, dict):
            fix_content = fixtext.get('#text', str(fixtext))
        elif isinstance(fixtext, list):
            fix_content = ' '.join([
                item.get('#text', str(item)) if isinstance(item, dict) else str(item)
                for item in fixtext
            ])
        else:
            fix_content = str(fixtext)

    control['fix'] = str(fix_content).strip()

    # Add RHEL version
    control['rhel_version'] = rhel_version

    # Extract additional metadata
    if 'ident' in rule:
        ident = rule['ident']
        if isinstance(ident, list):
            for ident_item in ident:
                if isinstance(ident_item, dict):
                    system = ident_item.get('@system', '')
                    if 'CCI' in system:
                        control['cci'] = ident_item.get('#text', '')
        elif isinstance(ident, dict):
            control['cci'] = ident.get('#text', '')

    # Extract references
    if 'reference' in rule:
        ref = rule['reference']
        if isinstance(ref, dict):
            control['reference'] = ref.get('@href', '')

    return control

def process_stig_xml(xml_path, rhel_version):
    """Process a STIG XML file and return parsed controls"""
    print(f"Converting and parsing XML: {xml_path}")
    
    # Convert XML to JSON
    json_data = xml_to_json(xml_path)
    if not json_data:
        print(f"Failed to convert {xml_path} to JSON")
        return {}
    
    # Extract benchmark data
    benchmark_data = json_data.get('Benchmark', {})
    if not benchmark_data:
        print(f"No Benchmark data found in {xml_path}")
        return {}
    
    # Parse controls from benchmark
    controls = extract_controls_from_benchmark(benchmark_data, rhel_version)
    print(f"Extracted {len(controls)} controls from {os.path.basename(xml_path)}")
    
    return controls

def main():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    os.makedirs(EXTRACT_DIR, exist_ok=True)

    all_controls = {}
    raw_stig_data = []  # Optional: keep raw data for debugging

    # Process RHEL 8
    print("\n--- Processing RHEL 8 STIG ---")
    rhel8_zip_filename = os.path.basename(RHEL8_STIG_URL)
    rhel8_zip_path = os.path.join(DOWNLOAD_DIR, rhel8_zip_filename)

    if download_file(RHEL8_STIG_URL, rhel8_zip_path):
        rhel8_extract_path = os.path.join(EXTRACT_DIR, "rhel8_stig")
        os.makedirs(rhel8_extract_path, exist_ok=True)
        if unzip_file(rhel8_zip_path, rhel8_extract_path):
            # Find and process all XML files
            for root, _, files in os.walk(rhel8_extract_path):
                for file in files:
                    if file.lower().endswith(('.xml', '.xccdf')):
                        xml_path = os.path.join(root, file)
                        
                        # Process XML and extract controls
                        controls = process_stig_xml(xml_path, "8")
                        all_controls.update(controls)
                        
                        # Optional: keep raw data too
                        json_data = xml_to_json(xml_path)
                        if json_data:
                            raw_stig_data.append({
                                "rhel_version": "8", 
                                "source_file": file, 
                                "data": json_data
                            })
    else:
        print("Skipping RHEL 8 STIG processing due to download failure.")

    # Process RHEL 9
    print("\n--- Processing RHEL 9 STIG ---")
    rhel9_zip_filename = os.path.basename(RHEL9_STIG_URL)
    rhel9_zip_path = os.path.join(DOWNLOAD_DIR, rhel9_zip_filename)

    if download_file(RHEL9_STIG_URL, rhel9_zip_path):
        rhel9_extract_path = os.path.join(EXTRACT_DIR, "rhel9_stig")
        os.makedirs(rhel9_extract_path, exist_ok=True)
        if unzip_file(rhel9_zip_path, rhel9_extract_path):
            # Find and process all XML files
            for root, _, files in os.walk(rhel9_extract_path):
                for file in files:
                    if file.lower().endswith(('.xml', '.xccdf')):
                        xml_path = os.path.join(root, file)
                        
                        # Process XML and extract controls
                        controls = process_stig_xml(xml_path, "9")
                        all_controls.update(controls)
                        
                        # Optional: keep raw data too
                        json_data = xml_to_json(xml_path)
                        if json_data:
                            raw_stig_data.append({
                                "rhel_version": "9", 
                                "source_file": file, 
                                "data": json_data
                            })
    else:
        print("Skipping RHEL 9 STIG processing due to download failure.")

    # Export parsed controls
    if all_controls:
        try:
            with open(OUTPUT_JSON_FILE, 'w', encoding='utf-8') as f:
                json.dump(all_controls, f, indent=4)
            print(f"\n✅ Successfully exported {len(all_controls)} parsed STIG controls to {OUTPUT_JSON_FILE}")
            
            # Show sample of what we extracted
            print(f"\nSample controls extracted:")
            for i, (control_id, control_data) in enumerate(list(all_controls.items())[:3]):
                print(f"  {i+1}. {control_id}")
                print(f"     Title: {control_data.get('title', 'No title')[:60]}...")
                print(f"     RHEL: {control_data.get('rhel_version', 'Unknown')}")
                print(f"     Severity: {control_data.get('severity', 'Unknown')}")
                
        except Exception as e:
            print(f"Error writing parsed controls to file: {e}")
    else:
        print("\nNo STIG controls were successfully parsed.")

    # Optional: Also save raw data for debugging
    if raw_stig_data:
        try:
            with open(RAW_JSON_FILE, 'w', encoding='utf-8') as f:
                json.dump(raw_stig_data, f, indent=4)
            print(f"\n📋 Also saved raw STIG data to {RAW_JSON_FILE} for debugging")
        except Exception as e:
            print(f"Error writing raw data to file: {e}")

    print(f"\n🎯 Processing complete!")
    print(f"   Parsed controls: {len(all_controls)}")
    print(f"   Raw files processed: {len(raw_stig_data)}")

    # Optional cleanup
    # import shutil
    # shutil.rmtree(DOWNLOAD_DIR)
    # shutil.rmtree(EXTRACT_DIR)
    # print("Cleaned up download and extraction directories.")

if __name__ == "__main__":
    main()
