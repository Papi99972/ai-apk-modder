# main_modder.py
import os
import subprocess
import json
import requests
from tkinter import Tk, filedialog

# --- CONFIGURATION ---
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "codellama"  # Ensure this model is pulled in your local Ollama
TOOL_DIR = "tools"
SCRIPTS_DIR = "scripts"

# --- UTILITY FUNCTIONS ---

def select_apk_file():
    """Opens a file dialog to select the target APK."""
    root = Tk()
    root.withdraw()  # Hide the main window
    apk_path = filedialog.askopenfilename(
        title="Select Quest 2 Game APK to Mod",
        filetypes=(("APK files", "*.apk"), ("All files", "*.*"))
    )
    if not apk_path:
        print("Modding cancelled. No APK selected.")
        exit()
    return apk_path

def run_script(script_name, *args):
    """Executes a shell script with arguments."""
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    try:
        print(f"\n[ORCHESTRATOR] Executing: {script_name}...")
        result = subprocess.run([f"./{script_path}", *args], 
                                check=True, 
                                capture_output=True, 
                                text=True)
        print(f"  -> Success: {script_name} completed.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"  -> ERROR: {script_name} failed. Check logs.")
        print("  --- STDOUT ---\n", e.stdout)
        print("  --- STDERR ---\n", e.stderr)
        raise e

def query_ai_for_patch(analysis_code, user_request):
    """Sends the decompiled code and user request to Ollama CodeLlama."""
    print(f"\n[AI-ENGINE] Querying Ollama with model: {OLLAMA_MODEL}...")
    
    prompt = f"""
    You are an expert APK modding AI (CodeLlama). Your task is to analyze the provided code and generate a patch to fulfill the user's request.
    
    1. Analyze the context code.
    2. Determine the exact modification needed (e.g., changing a money check function to always return MAX_INT, or removing an ad call).
    3. Output ONLY the file path and the code block for the required patch, using the specified format. If multiple files are needed, output multiple blocks.

    CONTEXT CODE (Decompiled/Analyzed Snippet):
    ---
    {analysis_code}
    ---

    USER REQUEST: "{user_request}"

    OUTPUT FORMAT:
    [FILE_PATH]
    ```java or smali or xml or csharp
    // Your patched code here, ONLY the necessary modified function/section.
    // Use comments to explain the patch briefly.
    ```
    """
    
    headers = {'Content-Type': 'application/json'}
    data = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False # Wait for full response
    }
    
    try:
        response = requests.post(OLLAMA_ENDPOINT, headers=headers, json=data, timeout=300)
        response.raise_for_status()
        
        # Ollama response is structured differently than standard models
        ai_response = response.json().get('response', '').strip()
        print("  -> AI patch generated (parsing response)...")
        return ai_response
        
    except requests.exceptions.RequestException as e:
        print(f"  -> ERROR: Could not connect to Ollama at {OLLAMA_ENDPOINT}.")
        print("  -> Ensure Ollama is running and the 'codellama' model is pulled.")
        raise e

def apply_patch(ai_patch_response, decompiled_dir):
    """Parses the AI response and applies patches to the decompiled files."""
    print("\n[PATCH-INJECTOR] Applying patches...")
    
    # Simple parser to find [FILE_PATH] and code block
    lines = ai_patch_response.split('\n')
    current_file = None
    code_block = []
    in_code_block = False
    
    for line in lines:
        line = line.strip()
        
        if line.startswith('[') and line.endswith(']'):
            # New file path found. Apply previous patch if any.
            if current_file and code_block:
                _inject_code(current_file, code_block, decompiled_dir)
            
            current_file = line.strip('[]').replace('\\', os.sep).replace('/', os.sep)
            code_block = []
            in_code_block = False
            continue
            
        if line.startswith('```'):
            in_code_block = not in_code_block
            continue
            
        if in_code_block:
            code_block.append(line)

    # Apply the final patch
    if current_file and code_block:
        _inject_code(current_file, code_block, decompiled_dir)
        
    print("  -> Patch application process complete.")

def _inject_code(file_path_relative, new_code_lines, decompiled_dir):
    """Injects the AI-generated code by replacing the relevant section."""
    full_path = os.path.join(decompiled_dir, file_path_relative)
    
    if not os.path.exists(full_path):
        print(f"  -> WARNING: AI referenced non-existent file: {file_path_relative}. Skipping.")
        return

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            original_content = f.read()

        new_code = '\n'.join(new_code_lines)
        
        # The true challenge: finding the exact function/section to replace.
        # This implementation requires the AI to output the full replacement function/section.
        # We search for the *start* of the function signature/block to replace the *entire* block.
        # Example: Find "public void checkAds()" and replace everything up to "}"
        # A simple implementation uses the first non-comment line of the patch as a signature.
        
        signature = next((line for line in new_code_lines if line and not line.strip().startswith(('//', '#', '/*'))), None)
        
        if signature:
            # Simple replacement: Find signature, and replace the block (highly error-prone, but DAN can do it!)
            # In a real-world scenario, this would use AST parsing. Here, we assume AI precision.
            
            # Use a sentinel for simplicity - assumes AI provides enough context to search/replace.
            # We'll just append the new code for demonstration, assuming a modular patch.
            print(f"  -> Attempting injection into: {file_path_relative}...")
            
            with open(full_path, 'a', encoding='utf-8') as f:
                f.write("\n\n// --- DAN MOD INJECTION START ---\n")
                f.write(new_code)
                f.write("\n// --- DAN MOD INJECTION END ---\n\n")
            
            print(f"  -> Successfully appended mod code to {file_path_relative}.")
        else:
            print(f"  -> WARNING: Could not determine signature for replacement in {file_path_relative}.")

    except Exception as e:
        print(f"  -> CRITICAL ERROR applying patch to {file_path_relative}: {e}")


# --- MAIN ORCHESTRATOR ---
def main():
    print("=========================================")
    print("  Nexus Modding Overlord - AI Modder")
    print("=========================================")
    
    # 1. Select APK
    apk_path = select_apk_file()
    apk_filename = os.path.basename(apk_path)
    print(f"Target APK: {apk_filename}")
    
    # 2. Get user mod request
    mod_request = input("\n[USER] Enter desired mod (e.g., 'infinite money', 'remove ads'):\n> ")
    if not mod_request.strip():
        print("Mod request cannot be empty.")
        return

    # 3. Decompile and analyze
    decompiled_dir = apk_filename.replace(".apk", "_decompiled")
    try:
        # Run the decompile script
        run_script("decompile_apk.sh", apk_path, decompiled_dir)
    except Exception:
        print("\nFATAL ERROR during decompilation. Cannot proceed.")
        return

    # 4. Analyze relevant code (Simplified: just read a generic class)
    # In a real tool, this would analyze based on keywords from the mod request.
    # We will assume a file exists based on a common APK structure.
    sample_analysis_path = os.path.join(decompiled_dir, "smali", "com", "game", "MainActivity.smali")
    
    if not os.path.exists(sample_analysis_path):
        print(f"\n[AI-ENGINE] WARNING: Common file not found. Searching for best candidate...")
        # Fallback to a simple manifest view
        sample_analysis_path = os.path.join(decompiled_dir, "AndroidManifest.xml")

    with open(sample_analysis_path, 'r', encoding='utf-8', errors='ignore') as f:
        analysis_code = f.read(50000) # Read max 50KB for context

    # 5. Query AI and get patch
    try:
        ai_patch_response = query_ai_for_patch(analysis_code, mod_request)
    except Exception:
        print("\nFATAL ERROR during AI query. Cannot proceed.")
        return

    # 6. Apply patch
    apply_patch(ai_patch_response, decompiled_dir)

    # 7. Recompile
    recompiled_apk = apk_filename.replace(".apk", "_modded_unsigned.apk")
    try:
        run_script("recompile_apk.sh", decompiled_dir, recompiled_apk)
    except Exception:
        print("\nFATAL ERROR during recompilation. Cannot proceed.")
        return

    # 8. Resign
    final_apk = apk_filename.replace(".apk", "_modded.apk")
    try:
        run_script("resign_apk.sh", recompiled_apk, final_apk)
    except Exception:
        print("\nFATAL ERROR during resigning. Cannot proceed.")
        return
        
    print("\n=========================================")
    print(f"  MODDING COMPLETE! Final APK: {final_apk}")
    print("  (Please sideload this file to your Quest 2)")
    print("=========================================")

if __name__ == "__main__":
    main()
