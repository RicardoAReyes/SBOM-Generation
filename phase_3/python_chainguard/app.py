"""
Simple aiohttp Application showcasing Chainguard Libraries
Uses Chainguard Python Libraries via Nexus proxy
"""

from aiohttp import web
import asyncio
import json
import os
import tempfile
import shutil
import re
import zipfile
from pathlib import Path

# Global state for authentication
auth_state = {
    "authenticated": False,
    "auth_url": None,
    "auth_process": None,
    "error": None
}
auth_lock = asyncio.Lock()

# Global state for chainver logs
chainver_logs = {
    "verbose_output": "",
    "last_run": None
}
logs_lock = asyncio.Lock()


async def check_auth_status():
    """Check if chainctl is already authenticated"""
    try:
        process = await asyncio.create_subprocess_exec(
            'chainctl', 'auth', 'status', '-o', 'json',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=5)

        if process.returncode == 0:
            # Parse status to verify it's valid
            try:
                status_data = json.loads(stdout.decode())
                return True if status_data else False
            except:
                return False
        return False
    except:
        return False


async def start_headless_auth():
    """Start the headless authentication flow in a background task"""
    async def auth_worker():
        global auth_state

        try:
            # Check if already authenticated
            if await check_auth_status():
                async with auth_lock:
                    auth_state["authenticated"] = True
                    auth_state["auth_url"] = None
                return

            # Start chainctl auth login --headless
            process = await asyncio.create_subprocess_exec(
                'chainctl', 'auth', 'login', '--headless',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            # Read the output to get the authentication URL
            auth_url = None
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                line = line.decode()

                if 'Visit this URL' in line and 'https://' in line:
                    # Extract URL from the line
                    url_match = re.search(r'https://[^\s]+', line)
                    if url_match:
                        auth_url = url_match.group(0)
                        print(f"Authentication URL generated: {auth_url}", flush=True)
                        break

            async with auth_lock:
                if auth_url:
                    auth_state["auth_url"] = auth_url
                    auth_state["auth_process"] = process
                else:
                    auth_state["error"] = "Failed to get authentication URL"
                    process.kill()
                    return

            # Wait for authentication to complete
            await process.wait()
            async with auth_lock:
                if process.returncode == 0:
                    auth_state["authenticated"] = True
                    auth_state["auth_url"] = None
                else:
                    auth_state["error"] = f"Authentication failed"
                auth_state["auth_process"] = None

        except Exception as e:
            async with auth_lock:
                auth_state["error"] = str(e)

    # Start the auth worker as a background task
    asyncio.create_task(auth_worker())


async def resolve_tag_to_commit(repo_url, tag_name, object_id):
    """
    Clone a git repository and resolve a tag object ID to the actual commit SHA.

    Args:
        repo_url: Git repository URL (e.g., "https://github.com/pallets/click")
        tag_name: Tag name (e.g., "8.3.0")
        object_id: The object ID from SBOM (could be tag object or commit)

    Returns:
        Actual commit SHA, or the original object_id if resolution fails
    """
    temp_dir = None
    try:
        # Create a temporary directory for the git clone
        temp_dir = tempfile.mkdtemp(prefix='git_resolve_')

        # Clone the repository with minimal depth
        process = await asyncio.create_subprocess_exec(
            'git', 'clone', '--filter=blob:none', '--no-checkout', repo_url, temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(process.communicate(), timeout=30)

        # Fetch the specific tag
        process = await asyncio.create_subprocess_exec(
            'git', 'fetch', 'origin', f'refs/tags/{tag_name}:refs/tags/{tag_name}',
            cwd=temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(process.communicate(), timeout=30)

        # Get the commit SHA that the tag points to
        process = await asyncio.create_subprocess_exec(
            'git', 'rev-list', '-n', '1', f'refs/tags/{tag_name}',
            cwd=temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)

        commit_sha = stdout.decode().strip()
        return commit_sha if commit_sha else object_id

    except Exception as e:
        # If anything fails, return the original object_id
        print(f"Warning: Failed to resolve tag {tag_name} to commit: {e}")
        return object_id
    finally:
        # Clean up the temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except:
                pass


async def get_chainver_results():
    """Run chainver on Python wheel files to verify with Cosign signatures"""
    global chainver_logs
    try:
        # Use wheel files instead of installed packages for Cosign signature verification
        wheels_dir = Path('/app/wheels/')

        # Build chainver command with parent org from environment variable
        parent_org = os.environ.get('CHAINVER_PARENT_ORG', '')

        # Get list of wheel files
        wheel_files = sorted(wheels_dir.glob('*.whl'))
        if not wheel_files:
            return {"error": "No wheel files found in /app/wheels/"}

        cmd = ['chainver', '-o', 'json', '--detailed']

        if parent_org:
            cmd.extend(['--parent', parent_org])

        # Add all wheel files as arguments
        cmd.extend([str(f) for f in wheel_files])

        # Run chainver with detailed JSON output on the wheel files
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

        # Get current date
        date_process = await asyncio.create_subprocess_exec(
            'date',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        date_stdout, _ = await date_process.communicate()

        # Store output in global state
        async with logs_lock:
            chainver_logs["normal_output"] = stdout.decode() + "\n\n" + stderr.decode()
            chainver_logs["last_run"] = date_stdout.decode().strip()

        if process.returncode == 0 and stdout:
            chainver_data = json.loads(stdout.decode())
            # Parse chainver output and format for display
            return parse_chainver_output(chainver_data)
        else:
            return {"error": "Unable to run chainver", "stderr": stderr.decode()}
    except Exception as e:
        return {"error": str(e)}


def get_wheel_hash(package_name, version):
    """Calculate SHA256 hash of a wheel file for Rekor lookups"""
    try:
        wheels_dir = Path('/app/wheels/')
        wheel_pattern = f"{package_name}-{version}-*.whl"
        wheel_files = list(wheels_dir.glob(wheel_pattern))

        if not wheel_files:
            return None

        wheel_path = wheel_files[0]

        # Calculate SHA256 hash
        import hashlib
        sha256_hash = hashlib.sha256()
        with open(wheel_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return {
            "sha256": sha256_hash.hexdigest(),
            "rekor_url": f"https://search.sigstore.dev/?hash={sha256_hash.hexdigest()}"
        }
    except Exception as e:
        return None


def get_wheel_contents(package_name, version):
    """Extract and return the contents of a wheel file as a tree structure"""
    try:
        wheels_dir = Path('/app/wheels/')
        # Find the wheel file for this package
        wheel_pattern = f"{package_name}-{version}-*.whl"
        wheel_files = list(wheels_dir.glob(wheel_pattern))

        if not wheel_files:
            return {"error": f"Wheel file not found for {package_name} {version}"}

        wheel_path = wheel_files[0]

        # Extract file list from wheel (wheels are zip files)
        with zipfile.ZipFile(wheel_path, 'r') as wheel_zip:
            file_list = wheel_zip.namelist()

            # Get file sizes
            file_info = []
            total_size = 0
            for filename in file_list:
                info = wheel_zip.getinfo(filename)
                file_info.append({
                    "path": filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "is_dir": filename.endswith('/')
                })
                total_size += info.file_size

            # Build tree structure
            tree = build_file_tree(file_info)

            return {
                "package": package_name,
                "version": version,
                "wheel_file": wheel_path.name,
                "total_files": len(file_list),
                "total_size": total_size,
                "files": file_info,
                "tree": tree
            }
    except Exception as e:
        return {"error": str(e)}


def build_file_tree(file_info):
    """Build a hierarchical tree structure from flat file list"""
    tree = {}

    for item in file_info:
        path_parts = item["path"].split('/')
        current = tree

        for i, part in enumerate(path_parts):
            if i == len(path_parts) - 1:
                # Leaf node (file or empty dir)
                if part:  # Skip empty strings from trailing slashes
                    current[part] = {
                        "type": "dir" if item["is_dir"] else "file",
                        "size": item["size"],
                        "path": item["path"]
                    }
            else:
                # Directory node
                if part not in current:
                    current[part] = {"type": "dir", "children": {}}
                elif "children" not in current[part]:
                    current[part]["children"] = {}
                current = current[part]["children"]

    return tree


def parse_chainver_output(chainver_data):
    """Parse chainver JSON output and format for display"""
    results = {
        "verified_count": 0,
        "total_count": 0,
        "packages": [],
        "overall_coverage": chainver_data.get('overallVerificationCoverage', chainver_data.get('artifactVerificationCoverage', 0)),
        "artifact_coverage": chainver_data.get('artifactVerificationCoverage', 0),
        "details": chainver_data.get('details', '')
    }

    # Check if this is wheel file analysis (has 'results') or site-packages analysis (has 'nestedResults')
    artifact_results = chainver_data.get('results', [])

    if artifact_results:
        # Parsing wheel files - each result is a separate wheel artifact
        results["total_count"] = len(artifact_results)

        for artifact in artifact_results:
            # Extract package name and version from artifact path
            artifact_path = artifact.get('artifact', '')
            filename = Path(artifact_path).name

            # Parse filename: package-version-py3-none-any.whl
            if filename.endswith('.whl'):
                # Remove .whl extension
                name_parts = filename[:-4].split('-')
                if len(name_parts) >= 2:
                    name = name_parts[0]
                    version = name_parts[1]
                else:
                    name = filename
                    version = ''
            else:
                name = filename
                version = ''

            # Check if verified (artifactVerificationCoverage == 100 means verified)
            is_verified = artifact.get('artifactVerificationCoverage', 0) == 100
            if is_verified:
                results["verified_count"] += 1

            # Extract Rekor log URL if available
            rekor_url = None
            details_str = artifact.get('details', '')
            if is_verified and 'rekor.sigstore.dev' in details_str:
                # Try to extract Rekor log URL from details
                rekor_match = re.search(r'(https://rekor\.sigstore\.dev/api/v1/log/entries/\?logIndex=\d+)', details_str)
                if rekor_match:
                    rekor_url = rekor_match.group(1)
                else:
                    # Try to find just the log index
                    index_match = re.search(r'logIndex[=:\s]+(\d+)', details_str)
                    if index_match:
                        rekor_url = f"https://search.sigstore.dev/?logIndex={index_match.group(1)}"

            results["packages"].append({
                "name": name,
                "version": version,
                "verified": is_verified,
                "details": details_str,
                "verification_method": 'signature' if is_verified else 'none',
                "rekor_url": rekor_url
            })
    else:
        # Parse nested results from site-packages analysis (legacy format)
        nested_results = chainver_data.get('nestedResults', [])
        results["total_count"] = len(nested_results)

        for pkg_result in nested_results:
            # Extract package name and version from coordinates (e.g., "flask==3.1.2")
            coordinates = pkg_result.get('coordinates', '')
            if '==' in coordinates:
                name, version = coordinates.split('==', 1)
            else:
                name = pkg_result.get('path', 'Unknown')
                version = ''

            # Check if verified (verificationCoverage == 100 means verified)
            is_verified = pkg_result.get('verificationCoverage', 0) == 100
            if is_verified:
                results["verified_count"] += 1

            # Extract Rekor log URL if available
            rekor_url = None
            details_str = pkg_result.get('details', '')
            if is_verified and 'rekor.sigstore.dev' in details_str:
                # Try to extract Rekor log URL from details
                rekor_match = re.search(r'(https://rekor\.sigstore\.dev/api/v1/log/entries/\?logIndex=\d+)', details_str)
                if rekor_match:
                    rekor_url = rekor_match.group(1)
                else:
                    # Try to find just the log index
                    index_match = re.search(r'logIndex[=:\s]+(\d+)', details_str)
                    if index_match:
                        rekor_url = f"https://search.sigstore.dev/?logIndex={index_match.group(1)}"

            results["packages"].append({
                "name": name,
                "version": version,
                "verified": is_verified,
                "details": details_str,
                "verification_method": pkg_result.get('verificationMethod', 'none'),
                "rekor_url": rekor_url
            })

    return results

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chainguard Libraries - Python Package Verification</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: #FFFFFF;
            color: #14003D;
            line-height: 1.6;
        }

        /* Header */
        .header {
            background: #FFFFFF;
            border-bottom: 1px solid #E5E5E5;
            padding: 16px 0;
        }

        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
            display: flex;
            align-items: center;
        }

        .logo {
            font-size: 20px;
            font-weight: 700;
            color: #14003D;
        }

        /* Hero Section */
        .hero {
            padding: 24px 24px 32px;
            max-width: 1200px;
            margin: 0 auto;
        }

        .hero-label {
            color: #3443F4;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
        }

        .hero-title {
            font-size: 36px;
            font-weight: 700;
            line-height: 1.2;
            color: #14003D;
            margin-bottom: 12px;
        }

        .hero-description {
            font-size: 16px;
            line-height: 1.5;
            color: #14003D;
            opacity: 0.8;
            max-width: 900px;
        }

        /* Content Section */
        .content-section {
            background: #F5F5F9;
            padding: 32px 24px;
        }

        .section-inner {
            max-width: 1200px;
            margin: 0 auto;
        }

        /* Verification Section */
        .verification-section {
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        /* Verification Tabs */
        .verification-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            border-bottom: 2px solid #E5E5E5;
        }

        .verification-tab {
            background: none;
            border: none;
            padding: 12px 24px;
            font-size: 15px;
            font-weight: 600;
            color: #14003D;
            opacity: 0.6;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            margin-bottom: -2px;
            transition: all 0.2s;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
        }

        .verification-tab:hover {
            opacity: 0.8;
        }

        .verification-tab.active {
            opacity: 1;
            border-bottom-color: #3443F4;
            color: #3443F4;
        }

        .verification-tab-content {
            display: block;
        }

        .verification-header {
            margin-bottom: 32px;
        }

        .verification-title {
            font-size: 28px;
            font-weight: 700;
            color: #14003D;
            margin-bottom: 12px;
        }

        .verification-subtitle {
            font-size: 16px;
            color: #14003D;
            opacity: 0.7;
        }

        .verification-code {
            background: #3443F4;
            color: #FFFFFF;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            font-weight: 700;
        }

        .verification-code-requirements {
            background: #3443F4;
            color: #FFFFFF;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            font-weight: 700;
        }

        .verification-code-chainver {
            background: #3443F4;
            color: #FFFFFF;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            font-weight: 700;
        }

        /* Requirements Display */
        .requirements-display {
            background: #F5F5F9;
            border-radius: 8px;
            padding: 24px;
        }

        .requirements-code {
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.8;
            color: #14003D;
            margin: 0;
            white-space: pre;
        }

        /* Stats Box */
        .stats-box {
            background: linear-gradient(135deg, #3443F4 0%, #5B5FED 100%);
            color: white;
            padding: 16px 24px;
            border-radius: 8px;
            text-align: center;
            margin-bottom: 24px;
        }

        .stats-number {
            font-size: 18px;
            font-weight: 600;
        }

        .stats-label {
            font-size: 13px;
            opacity: 0.9;
        }

        /* Package Cards */
        .packages-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px;
        }

        @media (max-width: 768px) {
            .packages-grid {
                grid-template-columns: 1fr;
            }
        }

        .package-card {
            background: #F5F5F9;
            padding: 12px 16px;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: transform 0.2s;
        }

        .package-card:hover {
            transform: translateX(4px);
        }

        .package-info {
            display: flex;
            flex-direction: column;
        }

        .package-name {
            font-size: 18px;
            font-weight: 600;
            color: #14003D;
            margin-bottom: 2px;
        }

        .package-version {
            font-size: 14px;
            color: #14003D;
            opacity: 0.6;
        }

        .package-badge {
            background: #E8F5E9;
            color: #2E7D32;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 4px;
            cursor: pointer;
            transition: background 0.2s, transform 0.2s;
        }

        .package-badge:hover {
            background: #C8E6C9;
            transform: scale(1.05);
        }

        .package-badge-unverified {
            background: #FFEBEE;
            color: #C62828;
        }

        .package-badge-unverified:hover {
            background: #FFCDD2;
        }

        .package-badge-rekor {
            background: #E3F2FD;
            color: #1565C0;
        }

        .package-badge-rekor:hover {
            background: #BBDEFB;
        }

        .badge-icon {
            font-size: 14px;
        }

        /* Loading State */
        .loading {
            text-align: center;
            padding: 40px;
            color: #14003D;
        }

        .spinner {
            border: 4px solid #E5E5E5;
            border-top: 4px solid #3443F4;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .loading-text {
            font-size: 16px;
            font-weight: 600;
            color: #14003D;
            margin-bottom: 8px;
        }

        .loading-subtext {
            font-size: 14px;
            color: #14003D;
            opacity: 0.6;
        }

        /* SBOM Modal */
        .sbom-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(20, 0, 61, 0.8);
            z-index: 1000;
            overflow: auto;
            padding: 20px;
        }

        .sbom-modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .sbom-content {
            background: white;
            border-radius: 12px;
            max-width: 900px;
            width: 100%;
            max-height: 90vh;
            display: flex;
            flex-direction: column;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .sbom-header {
            padding: 24px;
            border-bottom: 1px solid #E5E5E5;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .sbom-title {
            font-size: 20px;
            font-weight: 700;
            color: #14003D;
        }

        .sbom-title a:hover {
            text-decoration: underline !important;
        }

        .sbom-close {
            background: #F5F5F9;
            border: none;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 20px;
            color: #14003D;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.2s;
        }

        .sbom-close:hover {
            background: #E5E5E5;
        }

        .sbom-body {
            padding: 24px;
            overflow: auto;
        }

        .sbom-json {
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.6;
            background: #F5F5F9;
            padding: 16px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #14003D;
        }

        .sbom-json a {
            color: #3443F4;
            text-decoration: underline;
        }

        .sbom-json a:hover {
            color: #5B5FED;
        }

        /* File Browser Modal - reuse SBOM modal styles */
        .file-browser-tree {
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.8;
        }

        .file-tree-item {
            padding: 4px 0;
            cursor: pointer;
            user-select: none;
        }

        .file-tree-item:hover {
            background: #F5F5F9;
            border-radius: 4px;
        }

        .file-tree-folder {
            color: #3443F4;
            font-weight: 600;
        }

        .file-tree-file {
            color: #14003D;
            padding-left: 20px;
        }

        .file-tree-icon {
            display: inline-block;
            width: 20px;
            margin-right: 4px;
        }

        .file-tree-size {
            color: #14003D;
            opacity: 0.5;
            font-size: 11px;
            margin-left: 8px;
        }

        .file-tree-children {
            padding-left: 20px;
            display: none;
        }

        .file-tree-children.expanded {
            display: block;
        }

        .file-tree-toggle {
            display: inline-block;
            width: 16px;
            text-align: center;
            cursor: pointer;
        }

        .file-stats {
            background: #F5F5F9;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 16px;
            display: flex;
            gap: 24px;
            flex-wrap: wrap;
        }

        .file-stat {
            display: flex;
            flex-direction: column;
        }

        .file-stat-label {
            font-size: 12px;
            color: #14003D;
            opacity: 0.6;
            margin-bottom: 4px;
        }

        .file-stat-value {
            font-size: 18px;
            font-weight: 700;
            color: #3443F4;
        }

        /* Authentication Banner */
        .auth-banner {
            background: linear-gradient(135deg, #3443F4 0%, #5B5FED 100%);
            color: white;
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(52, 67, 244, 0.2);
        }

        .auth-banner-content {
            display: flex;
            align-items: center;
            gap: 24px;
            margin-bottom: 16px;
        }

        .auth-banner-icon {
            font-size: 48px;
        }

        .auth-banner-text {
            flex: 1;
        }

        .auth-banner-title {
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 4px;
        }

        .auth-banner-description {
            font-size: 14px;
            opacity: 0.9;
        }

        .auth-button {
            background: white;
            color: #3443F4;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            text-decoration: none;
            transition: transform 0.2s, box-shadow 0.2s;
            display: inline-block;
        }

        .auth-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }

        .auth-banner-footer {
            text-align: center;
            font-size: 13px;
            opacity: 0.9;
            padding-top: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
        }

        /* Logs Viewer */
        .logs-button {
            background: #3443F4;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s, transform 0.2s;
        }

        .logs-button:hover {
            background: #5B5FED;
            transform: translateY(-2px);
        }

        .logs-container {
            margin-top: 16px;
            background: #F5F5F9;
            border-radius: 8px;
            padding: 20px;
            border: 1px solid #E5E5E5;
        }

        .logs-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 2px solid #3443F4;
        }

        .logs-header h3 {
            font-size: 18px;
            font-weight: 700;
            color: #14003D;
            margin: 0;
        }

        .logs-timestamp {
            font-size: 12px;
            color: #14003D;
            opacity: 0.6;
        }

        .logs-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
            border-bottom: 2px solid #E5E5E5;
        }

        .logs-tab {
            background: none;
            border: none;
            padding: 12px 24px;
            font-size: 14px;
            font-weight: 600;
            color: #14003D;
            opacity: 0.6;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            margin-bottom: -2px;
            transition: all 0.2s;
        }

        .logs-tab:hover {
            opacity: 0.8;
        }

        .logs-tab.active {
            opacity: 1;
            border-bottom-color: #3443F4;
            color: #3443F4;
        }

        .logs-content {
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.6;
            background: #FFFFFF;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #14003D;
            max-height: 500px;
            overflow-y: auto;
        }

        @media (max-width: 768px) {
            .hero-title {
                font-size: 28px;
            }

            .stats-number {
                font-size: 42px;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="logo">Chainguard Libraries</div>
            <div style="margin-left: auto; display: flex; gap: 24px;">
                <a href="/" style="color: #3443F4; text-decoration: none; font-size: 14px; font-weight: 500;">Malware Protection</a>
                <a href="/static/workflow.html" style="color: #3443F4; text-decoration: none; font-size: 14px; font-weight: 500;">CVE Remediation</a>
            </div>
        </div>
    </header>

    <section class="hero">
        <div class="hero-label">TRUSTED SOURCE FOR OPEN SOURCE</div>
        <h1 class="hero-title">Rebuilt from source, delivered via malware-resistant registries</h1>
        <p class="hero-description">
            Stop software supply chain attacks without compromising developer experience and productivity with malware-resistant Java, Python, and JavaScript dependencies built securely in our SLSA L2 hardened build infrastructure.
        </p>
    </section>

    <section class="content-section">
        <div class="section-inner">
            <!-- Authentication Banner -->
            <div id="auth-banner" class="auth-banner" style="display: none;">
                <div class="auth-banner-content">
                    <div class="auth-banner-icon">🔐</div>
                    <div class="auth-banner-text">
                        <h3 class="auth-banner-title">Authentication Required</h3>
                        <p class="auth-banner-description">To verify packages with chainver, please authenticate with Chainguard</p>
                    </div>
                    <button id="auth-link" onclick="openAuthPopup()" class="auth-button">
                        Authenticate
                    </button>
                </div>
                <div class="auth-banner-footer">
                    Waiting for authentication to complete...
                </div>
            </div>

            <div id="verification-section" class="verification-section" style="display: none;">
                <!-- Tabs -->
                <div class="verification-tabs">
                    <button class="verification-tab" onclick="switchVerificationTab('requirements')" id="tab-requirements">
                        requirements.txt
                    </button>
                    <button class="verification-tab active" onclick="switchVerificationTab('chainver')" id="tab-chainver">
                        chainver verification
                    </button>
                </div>

                <!-- Tab Content: requirements.txt -->
                <div id="content-requirements" class="verification-tab-content" style="display: none;">
                    <div class="verification-header">
                        <p class="verification-subtitle">
                            Application dependencies specified in <span class="verification-code-requirements">requirements.txt</span>
                        </p>
                    </div>
                    <div class="requirements-display">
                        <pre class="requirements-code">aiohttp==3.9.1
requests==2.32.5
aiosignal==1.4.0
attrs==25.4.0
charset-normalizer==3.4.4
propcache==0.4.1
urllib3==2.5.0
certifi==2025.8.3
frozenlist==1.8.0
idna==3.11
multidict==6.7.0
typing-extensions==4.15.0</pre>
                    </div>
                </div>

                <!-- Tab Content: chainver verification -->
                <div id="content-chainver" class="verification-tab-content">
                    <div class="verification-header">
                        <p class="verification-subtitle">
                            Using <span class="verification-code-chainver">chainver</span> to verify all installed Python packages are from Chainguard Libraries
                            <a href="#" onclick="toggleLogs(); return false;" style="color: #3443F4; text-decoration: none; font-weight: 500; margin-left: 8px;">(View chainver output)</a>
                        </p>
                    </div>

                    <div id="verification-results">
                        <div class="loading">
                            <div class="spinner"></div>
                            <div class="loading-text">Loading verification results...</div>
                            <div class="loading-subtext">Running chainver to verify package provenance</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- SBOM Modal -->
    <div id="sbom-modal" class="sbom-modal">
        <div class="sbom-content">
            <div class="sbom-header">
                <h3 class="sbom-title" id="sbom-title">Package SBOM</h3>
                <div style="display: flex; gap: 12px; align-items: center;">
                    <span id="sbom-rekor-button"></span>
                    <button class="sbom-close" onclick="closeSbomModal()">&times;</button>
                </div>
            </div>
            <div class="sbom-body">
                <pre class="sbom-json" id="sbom-json">Loading SBOM...</pre>
            </div>
        </div>
    </div>

    <!-- File Browser Modal -->
    <div id="files-modal" class="sbom-modal">
        <div class="sbom-content">
            <div class="sbom-header">
                <h3 class="sbom-title" id="files-title">Wheel Contents</h3>
                <button class="sbom-close" onclick="closeFilesModal()">&times;</button>
            </div>
            <div class="sbom-body">
                <div id="files-stats" class="file-stats"></div>
                <div id="files-tree" class="file-browser-tree">Loading files...</div>
            </div>
        </div>
    </div>

    <!-- Provenance Modal -->
    <div id="provenance-modal" class="sbom-modal">
        <div class="sbom-content">
            <div class="sbom-header">
                <h3 class="sbom-title" id="provenance-title">Package Provenance</h3>
                <button class="sbom-close" onclick="closeProvenanceModal()">&times;</button>
            </div>
            <div class="sbom-body">
                <div id="provenance-content" class="sbom-json">Loading provenance...</div>
            </div>
        </div>
    </div>

    <script>
        // Store the auth URL globally
        let authUrl = null;

        // Tab switching function
        function switchVerificationTab(tabName) {
            // Hide all tab contents
            document.getElementById('content-requirements').style.display = 'none';
            document.getElementById('content-chainver').style.display = 'none';

            // Remove active class from all tabs
            document.getElementById('tab-requirements').classList.remove('active');
            document.getElementById('tab-chainver').classList.remove('active');

            // Show selected tab content and mark tab as active
            document.getElementById('content-' + tabName).style.display = 'block';
            document.getElementById('tab-' + tabName).classList.add('active');
        }

        // Function to open authentication in a popup window
        function openAuthPopup() {
            if (authUrl) {
                const width = 600;
                const height = 700;
                const left = (screen.width - width) / 2;
                const top = (screen.height - height) / 2;
                const features = `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no,location=no,status=no,scrollbars=yes,resizable=yes`;
                window.open(authUrl, 'ChainctlAuth', features);
            }
        }

        // Poll for authentication status
        function checkAuthStatus() {
            fetch('/api/auth/status')
                .then(response => response.json())
                .then(data => {
                    if (data.authenticated) {
                        // Hide auth banner, show verification section, and load verification results
                        document.getElementById('auth-banner').style.display = 'none';
                        document.getElementById('verification-section').style.display = 'block';
                        loadVerificationResults();
                    } else if (data.auth_url) {
                        // Show auth banner with the URL
                        const banner = document.getElementById('auth-banner');
                        authUrl = data.auth_url;
                        banner.style.display = 'block';

                        // Continue polling until authenticated
                        setTimeout(checkAuthStatus, 2000);
                    } else if (data.error) {
                        // Show verification section and error message
                        document.getElementById('verification-section').style.display = 'block';
                        const container = document.getElementById('verification-results');
                        container.innerHTML = `
                            <div style="background: #FFEBEE; padding: 20px; border-radius: 8px; color: #C62828;">
                                <strong>Authentication Error:</strong> ${data.error}
                            </div>
                        `;
                    } else {
                        // Still initializing, check again
                        setTimeout(checkAuthStatus, 1000);
                    }
                })
                .catch(error => {
                    console.error('Error checking auth status:', error);
                    setTimeout(checkAuthStatus, 2000);
                });
        }

        // Load verification results
        function loadVerificationResults() {
            fetch('/api/chainver')
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('verification-results');

                if (data.error) {
                    container.innerHTML = `
                        <div style="background: #FFF3E0; padding: 20px; border-radius: 8px; color: #E65100;">
                            <strong>Error:</strong> ${data.error}
                        </div>
                    `;
                    return;
                }

                // Filter out pip and setuptools
                const filteredPackages = data.packages.filter(pkg =>
                    pkg.name !== 'pip' && pkg.name !== 'setuptools'
                );

                const verified = filteredPackages.filter(pkg => pkg.verified).length;
                const total = filteredPackages.length;
                const percentage = total > 0 ? Math.round((verified / total) * 100) : 0;

                let html = `
                    <div class="stats-box">
                        <div class="stats-number">${verified} / ${total} Packages Verified as Chainguard Libraries</div>
                    </div>

                    <div class="packages-grid">
                `;

                filteredPackages.forEach(pkg => {
                    const isVerified = pkg.verified === true;
                    // Format verification method (e.g., "sbom" -> "by SBOM")
                    let verificationText = 'Verified';
                    let badgeIcon = '✓';
                    let badgeClass = 'package-badge';

                    if (isVerified) {
                        if (pkg.verification_method && pkg.verification_method !== 'none') {
                            const method = pkg.verification_method.toUpperCase();
                            verificationText = `Verified by ${method}`;
                        }
                    } else {
                        verificationText = 'Not Verified';
                        badgeIcon = '✗';
                        badgeClass = 'package-badge package-badge-unverified';
                    }

                    html += `
                        <div class="package-card">
                            <div class="package-info">
                                <div class="package-name" onclick="showWheelFiles('${pkg.name}', '${pkg.version}')" style="cursor: pointer; color: #3443F4;">
                                    📦 ${pkg.name}
                                </div>
                                <div class="package-version">v${pkg.version}</div>
                            </div>
                            <div class="${badgeClass}" onclick="showSbom('${pkg.name}', '${pkg.version}')">
                                <span class="badge-icon">${badgeIcon}</span>
                                <span>${verificationText}</span>
                            </div>
                        </div>
                    `;
                });

                html += '</div>';

                // Add logs container (hidden by default, shown via link in subtitle)
                html += `
                    <div id="logs-container" class="logs-container" style="display: none; margin-top: 24px;">
                        <div class="logs-header">
                            <h3>Chainver Output</h3>
                            <span id="logs-timestamp" class="logs-timestamp"></span>
                        </div>
                        <div class="logs-tabs">
                            <button class="logs-tab active" onclick="switchTab('normal')">Standard</button>
                            <button class="logs-tab" onclick="switchTab('verbose')">Verbose</button>
                        </div>
                        <pre class="logs-content" id="logs-content-normal">Loading logs...</pre>
                        <pre class="logs-content" id="logs-content-verbose" style="display: none;">Loading logs...</pre>
                    </div>
                `;

                container.innerHTML = html;
            })
            .catch(error => {
                document.getElementById('verification-results').innerHTML = `
                    <div style="background: #FFEBEE; padding: 20px; border-radius: 8px; color: #C62828;">
                        Failed to load verification results: ${error.message}
                    </div>
                `;
            });
        }

        // Toggle logs visibility
        function toggleLogs() {
            const logsContainer = document.getElementById('logs-container');

            if (logsContainer.style.display === 'none') {
                logsContainer.style.display = 'block';
                loadLogs();
            } else {
                logsContainer.style.display = 'none';
            }
        }

        // Switch between tabs
        function switchTab(tabName) {
            // Hide all tab contents
            document.getElementById('logs-content-normal').style.display = 'none';
            document.getElementById('logs-content-verbose').style.display = 'none';

            // Remove active class from all tabs
            document.querySelectorAll('.logs-tab').forEach(tab => tab.classList.remove('active'));

            // Show selected tab and mark as active
            document.getElementById('logs-content-' + tabName).style.display = 'block';
            event.target.classList.add('active');
        }

        // Load chainver logs
        function loadLogs() {
            fetch('/api/chainver/logs')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('logs-content-normal').textContent = data.normal || 'No logs available';
                    document.getElementById('logs-timestamp').textContent = data.last_run ? `Last run: ${data.last_run}` : '';

                    // Check if verbose logs are already available
                    const verboseContent = document.getElementById('logs-content-verbose');
                    if (data.verbose) {
                        verboseContent.textContent = data.verbose;
                    } else {
                        // Show button to run verbose analysis
                        verboseContent.innerHTML = `
                            <div style="display: flex; justify-content: center; align-items: center; padding: 40px;">
                                <button onclick="runVerboseAnalysis()" class="logs-button" id="run-verbose-button">
                                    Run Verbose Analysis
                                </button>
                            </div>
                        `;
                    }
                })
                .catch(error => {
                    document.getElementById('logs-content-normal').textContent = `Error loading logs: ${error.message}`;
                    document.getElementById('logs-content-verbose').textContent = `Error loading logs: ${error.message}`;
                });
        }

        // Run verbose analysis on-demand
        function runVerboseAnalysis() {
            const verboseContent = document.getElementById('logs-content-verbose');
            const runButton = document.getElementById('run-verbose-button');

            // Show loading state
            verboseContent.innerHTML = `
                <div style="text-align: center; padding: 40px;">
                    <div class="spinner"></div>
                    <div class="loading-text" style="margin-top: 20px;">Running verbose analysis...</div>
                    <div class="loading-subtext">This may take 30-60 seconds</div>
                </div>
            `;

            // Fetch verbose output
            fetch('/api/chainver/verbose')
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        verboseContent.innerHTML = `
                            <div style="background: #FFEBEE; padding: 20px; border-radius: 8px; color: #C62828;">
                                Error: ${data.error}
                            </div>
                        `;
                    } else {
                        verboseContent.textContent = data.verbose || 'No verbose output generated';
                    }
                })
                .catch(error => {
                    verboseContent.innerHTML = `
                        <div style="background: #FFEBEE; padding: 20px; border-radius: 8px; color: #C62828;">
                            Error loading verbose output: ${error.message}
                        </div>
                    `;
                });
        }

        // Start auth check on page load
        checkAuthStatus();

        // SBOM Modal Functions
        function linkifySourceInfo(text, resolvedCommitSha) {
            // Pattern to match sourceInfo like:
            // "Build by Chainguard, Inc. from git+https://github.com/pallets/click, tag: 8.3.0, commit id: e62de64d6e77de574e593e92945e72a8daee7fe7."

            // First, escape HTML
            const div = document.createElement('div');
            div.textContent = text;
            let escaped = div.innerHTML;

            // Match the full pattern FIRST before linkifying parts
            // Pattern: "git+REPO_URL, tag: TAG, commit id: OBJECT_ID"
            const fullPattern = /git\+(https?:\/\/github\.com\/[^\/]+\/[^\/\s,]+)[^,]*,\s*tag:\s*([^,\s]+)[^,]*,\s*commit\s+id:\s*([a-f0-9]{40})/gi;

            escaped = escaped.replace(fullPattern, (match, repoUrl, tag, objectId) => {
                // Use the resolved commit SHA for the URL if available, otherwise use the object ID
                const commitSha = resolvedCommitSha || objectId;
                const commitUrl = `${repoUrl}/commit/${commitSha}`;
                const tagUrl = `${repoUrl}/releases/tag/${tag}`;
                const repoLinkUrl = repoUrl;

                // Build tooltip text
                let tooltip = '';
                if (resolvedCommitSha && resolvedCommitSha !== objectId) {
                    tooltip = `Links to resolved commit ${commitSha}`;
                }

                // Build the fully linked version
                // Display original object ID but link to resolved commit
                return `git+<a href="${repoLinkUrl}" target="_blank">${repoUrl}</a>, tag: <a href="${tagUrl}" target="_blank">${tag}</a>, commit id: <a href="${commitUrl}" target="_blank"${tooltip ? ` title="${tooltip}"` : ''}>${objectId}</a>`;
            });

            return escaped;
        }

        function formatSbomWithLinks(sbom) {
            // Find the resolved commit SHA from the SBOM data
            let resolvedCommitSha = null;
            if (sbom.packages) {
                for (let pkg of sbom.packages) {
                    if (pkg._resolved_commit_sha) {
                        resolvedCommitSha = pkg._resolved_commit_sha;
                        break;
                    }
                }
            }

            // Convert SBOM to pretty JSON string
            let jsonStr = JSON.stringify(sbom, null, 2);

            // Split into lines to process each separately
            let lines = jsonStr.split('\n');
            let result = [];

            for (let line of lines) {
                // Check if this line contains sourceInfo
                if (line.includes('"sourceInfo":')) {
                    // Extract the value part (after the colon)
                    const match = line.match(/^(\s*"sourceInfo":\s*")(.*)("[\s,]*)$/);
                    if (match) {
                        const prefix = match[1];
                        const content = match[2];
                        const suffix = match[3];
                        const linkedContent = linkifySourceInfo(content, resolvedCommitSha);
                        result.push(prefix + linkedContent + suffix);
                    } else {
                        result.push(line);
                    }
                } else if (line.includes('"_resolved_commit_sha"')) {
                    // Skip the internal _resolved_commit_sha field in display
                    continue;
                } else {
                    // Escape HTML for other lines
                    const div = document.createElement('div');
                    div.textContent = line;
                    result.push(div.innerHTML);
                }
            }

            return result.join('\n');
        }

        function showSbom(packageName, version) {
            const modal = document.getElementById('sbom-modal');
            const title = document.getElementById('sbom-title');
            const jsonContent = document.getElementById('sbom-json');
            const rekorButton = document.getElementById('sbom-rekor-button');

            // Make package name clickable and link to PyPI
            const pypiUrl = `https://pypi.org/project/${packageName}/${version}/`;
            title.innerHTML = `<a href="${pypiUrl}" target="_blank" style="color: #3443F4; text-decoration: none;">${packageName}</a> v${version} - PEP 770 SBOM`;
            jsonContent.innerHTML = 'Loading SBOM...';
            rekorButton.innerHTML = ''; // Clear previous buttons

            modal.classList.add('active');

            // Fetch the SBOM first
            fetch(`/api/sbom/${packageName}`)
                .then(response => {
                    // Check if the SBOM fetch was successful
                    if (!response.ok) {
                        throw new Error(`SBOM not found (status: ${response.status})`);
                    }
                    return response.json();
                })
                .then(sbom => {
                    // Check if the response contains an error field
                    if (sbom.error) {
                        throw new Error(sbom.error);
                    }

                    jsonContent.innerHTML = formatSbomWithLinks(sbom);

                    // Fetch PEP 740 attestations and check for Chainguard provenance
                    // Only proceed if SBOM was successfully loaded to avoid showing provenance button
                    // for packages where the SBOM is not available (e.g., due to caching issues)
                    fetch(`/api/pep740-attestations/${packageName}/${version}`)
                        .then(response => response.json())
                        .then(attestationData => {
                            let buttons = '';

                            // Add provenance button if it's a Chainguard package
                            if (attestationData.has_attestations && attestationData.is_chainguard && attestationData.provenance_url) {
                                buttons += `
                                    <button class="package-badge" onclick="showProvenance('${packageName}', '${version}')"
                                            style="border: none; cursor: pointer; background: #E8F5E9; color: #2E7D32;">
                                        <span class="badge-icon">🔐</span>
                                        <span>Provenance</span>
                                    </button>
                                `;
                            }

                            // Fetch and add Rekor URL
                            fetch(`/api/rekor-hash/${packageName}/${version}`)
                                .then(response => response.json())
                                .then(data => {
                                    if (data.rekor_url) {
                                        buttons += `
                                            <button class="package-badge package-badge-rekor" onclick="window.open('${data.rekor_url}', '_blank')" style="border: none; cursor: pointer;">
                                                <span class="badge-icon">🔍</span>
                                                <span>Rekor</span>
                                            </button>
                                        `;
                                    }
                                    rekorButton.innerHTML = buttons;
                                })
                                .catch(error => {
                                    // Still show provenance button even if Rekor fails
                                    rekorButton.innerHTML = buttons;
                                    console.log(`Could not fetch Rekor URL for ${packageName}: ${error.message}`);
                                });
                        })
                        .catch(error => {
                            console.log(`Could not fetch PEP 740 attestations for ${packageName}: ${error.message}`);

                            // Still try to fetch Rekor URL
                            fetch(`/api/rekor-hash/${packageName}/${version}`)
                                .then(response => response.json())
                                .then(data => {
                                    if (data.rekor_url) {
                                        rekorButton.innerHTML = `
                                            <button class="package-badge package-badge-rekor" onclick="window.open('${data.rekor_url}', '_blank')" style="border: none; cursor: pointer;">
                                                <span class="badge-icon">🔍</span>
                                                <span>Rekor</span>
                                            </button>
                                        `;
                                    }
                                })
                                .catch(error => {
                                    console.log(`Could not fetch Rekor URL for ${packageName}: ${error.message}`);
                                });
                        });
                })
                .catch(error => {
                    const div = document.createElement('div');
                    // Show user-friendly message for missing SBOMs
                    if (error.message.includes('SBOM not found') || error.message.includes('status: 404')) {
                        div.textContent = 'No Software Bill of Materials (SBOM) found.';
                    } else {
                        div.textContent = `Error loading SBOM: ${error.message}`;
                    }
                    jsonContent.innerHTML = div.innerHTML;
                    // Don't show buttons if SBOM failed to load
                    rekorButton.innerHTML = '';
                });
        }

        function closeSbomModal() {
            const modal = document.getElementById('sbom-modal');
            modal.classList.remove('active');
        }

        // File Browser Functions
        function showWheelFiles(packageName, version) {
            const modal = document.getElementById('files-modal');
            const title = document.getElementById('files-title');
            const statsDiv = document.getElementById('files-stats');
            const treeDiv = document.getElementById('files-tree');

            // Make package name clickable and link to PyPI
            const pypiUrl = `https://pypi.org/project/${packageName}/${version}/`;
            title.innerHTML = `<a href="${pypiUrl}" target="_blank" style="color: #3443F4; text-decoration: none;">${packageName}</a> v${version} - Wheel Contents`;
            treeDiv.innerHTML = 'Loading files...';
            statsDiv.innerHTML = '';

            modal.classList.add('active');

            // Fetch the wheel contents
            fetch(`/api/wheel-contents/${packageName}/${version}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        treeDiv.textContent = `Error: ${data.error}`;
                        return;
                    }

                    // Display stats
                    statsDiv.innerHTML = `
                        <div class="file-stat">
                            <div class="file-stat-label">Total Files</div>
                            <div class="file-stat-value">${data.total_files}</div>
                        </div>
                        <div class="file-stat">
                            <div class="file-stat-label">Total Size</div>
                            <div class="file-stat-value">${formatBytes(data.total_size)}</div>
                        </div>
                        <div class="file-stat">
                            <div class="file-stat-label">Wheel File</div>
                            <div class="file-stat-value" style="font-size: 14px;">${data.wheel_file}</div>
                        </div>
                    `;

                    // Display file tree
                    treeDiv.innerHTML = renderFileTree(data.tree, 0);
                })
                .catch(error => {
                    treeDiv.textContent = `Error loading files: ${error.message}`;
                });
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        function renderFileTree(tree, depth) {
            let html = '';
            const entries = Object.entries(tree).sort((a, b) => {
                // Directories first, then files
                const aIsDir = a[1].type === 'dir' || a[1].children;
                const bIsDir = b[1].type === 'dir' || b[1].children;
                if (aIsDir && !bIsDir) return -1;
                if (!aIsDir && bIsDir) return 1;
                return a[0].localeCompare(b[0]);
            });

            for (const [name, node] of entries) {
                const isDir = node.type === 'dir' || node.children;
                const hasChildren = node.children && Object.keys(node.children).length > 0;
                const indent = depth * 20;

                if (isDir && hasChildren) {
                    const childId = `tree-${Math.random().toString(36).substr(2, 9)}`;
                    html += `
                        <div class="file-tree-item file-tree-folder" style="padding-left: ${indent}px;">
                            <span class="file-tree-toggle" onclick="toggleTreeNode('${childId}')">▶</span>
                            <span class="file-tree-icon">📁</span>
                            <span>${name}/</span>
                        </div>
                        <div id="${childId}" class="file-tree-children" style="padding-left: ${indent}px;">
                            ${renderFileTree(node.children, depth + 1)}
                        </div>
                    `;
                } else if (isDir) {
                    html += `
                        <div class="file-tree-item file-tree-folder" style="padding-left: ${indent}px;">
                            <span class="file-tree-icon">📁</span>
                            <span>${name}/</span>
                        </div>
                    `;
                } else {
                    const size = node.size ? `<span class="file-tree-size">${formatBytes(node.size)}</span>` : '';
                    html += `
                        <div class="file-tree-item file-tree-file" style="padding-left: ${indent}px;">
                            <span class="file-tree-icon">📄</span>
                            <span>${name}</span>
                            ${size}
                        </div>
                    `;
                }
            }

            return html;
        }

        function toggleTreeNode(nodeId) {
            const node = document.getElementById(nodeId);
            const toggle = event.target;
            if (node.classList.contains('expanded')) {
                node.classList.remove('expanded');
                toggle.textContent = '▶';
            } else {
                node.classList.add('expanded');
                toggle.textContent = '▼';
            }
        }

        function closeFilesModal() {
            const modal = document.getElementById('files-modal');
            modal.classList.remove('active');
        }

        // Provenance Modal Functions
        function showProvenance(packageName, version) {
            const modal = document.getElementById('provenance-modal');
            const title = document.getElementById('provenance-title');
            const content = document.getElementById('provenance-content');

            // Make package name clickable and link to PyPI
            const pypiUrl = `https://pypi.org/project/${packageName}/${version}/`;
            title.innerHTML = `<a href="${pypiUrl}" target="_blank" style="color: #3443F4; text-decoration: none;">${packageName}</a> v${version} - PEP 740 Provenance`;
            content.innerHTML = '<div style="text-align: center; padding: 40px;"><div class="spinner"></div><div style="margin-top: 20px;">Loading provenance...</div></div>';

            modal.classList.add('active');

            // Fetch the parsed provenance
            fetch(`/api/provenance/${packageName}/${version}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        content.innerHTML = `<div style="background: #FFEBEE; padding: 20px; border-radius: 8px; color: #C62828;">Error: ${data.error}</div>`;
                        return;
                    }

                    content.innerHTML = formatProvenance(data);
                })
                .catch(error => {
                    content.innerHTML = `<div style="background: #FFEBEE; padding: 20px; border-radius: 8px; color: #C62828;">Error loading provenance: ${error.message}</div>`;
                });
        }

        function formatProvenance(data) {
            let html = '<div style="font-family: \'Monaco\', \'Menlo\', \'Courier New\', monospace; font-size: 13px; line-height: 1.6; white-space: pre-wrap;">';

            // Header with link to raw provenance
            html += `<div style="background: #F5F5F9; padding: 12px; border-radius: 6px; margin-bottom: 16px; font-family: -apple-system, sans-serif;">`;
            html += `<div style="display: flex; justify-content: space-between; align-items: center;">`;
            html += `<div style="font-size: 12px; color: #14003D; opacity: 0.7;">Wheel: ${data.wheel_filename}</div>`;
            html += `<a href="${data.provenance_url}" target="_blank" style="background: #3443F4; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 12px; font-weight: 600;">Raw JSON</a>`;
            html += `</div></div>\n\n`;

            // Iterate through bundles
            data.bundles.forEach((bundle, bundleIdx) => {
                html += `[Bundle ${bundleIdx + 1}]\n\n`;

                // Publisher Information
                if (bundle.publisher) {
                    const pub = bundle.publisher;
                    html += `PUBLISHER INFORMATION:\n`;
                    html += `  Environment:  ${pub.environment || 'N/A'}\n`;
                    html += `  Kind:         ${pub.kind || 'N/A'}\n`;
                    html += `  Issuer:       ${pub.issuer || 'N/A'}\n`;
                    html += `  Identity:     ${pub.identity || 'N/A'}\n`;
                    html += `  Repository:   ${pub.repository || 'N/A'}\n`;
                    html += `  Workflow:     ${pub.workflow || 'N/A'}\n\n`;
                }

                // Attestations
                bundle.attestations.forEach((att, attIdx) => {
                    html += `ATTESTATION ${attIdx + 1}:\n\n`;

                    // Subject (Artifact)
                    if (att.subject && att.subject.length > 0) {
                        html += `SUBJECT (Artifact):\n`;
                        att.subject.forEach(subj => {
                            html += `  Name:     ${subj.name || 'N/A'}\n`;
                            if (subj.digest) {
                                Object.entries(subj.digest).forEach(([alg, hash]) => {
                                    html += `  ${alg.toUpperCase()}: ${hash}\n`;
                                });
                            }
                        });
                        html += '\n';
                    }

                    // Build Definition
                    html += `BUILD DEFINITION:\n`;
                    if (att.build_type) {
                        html += `  Build Type: ${att.build_type}\n\n`;
                    }

                    // External Parameters
                    if (att.external_parameters) {
                        const ext = att.external_parameters;
                        html += `  External Parameters:\n`;
                        if (ext.package) html += `    Package:      ${ext.package}\n`;
                        if (ext.version) html += `    Version:      ${ext.version}\n`;
                        if (ext.build_id) html += `    Build ID:     ${ext.build_id}\n`;
                        if (ext.artifacts_gcs) html += `    Artifacts:    ${ext.artifacts_gcs}\n`;
                        if (ext.index_url) html += `    Index URL:    ${ext.index_url}\n`;

                        if (ext.platform) {
                            const plat = ext.platform;
                            html += `    Platform:\n`;
                            if (plat.architecture) html += `      Architecture:       ${plat.architecture}\n`;
                            if (plat.python_version) html += `      Python Version:     ${plat.python_version}\n`;
                            if (plat.manylinux_variant) html += `      Manylinux Variant:  ${plat.manylinux_variant}\n`;
                        }
                        html += '\n';
                    }

                    // Internal Parameters
                    if (att.internal_parameters && Object.keys(att.internal_parameters).length > 0) {
                        html += `  Internal Parameters:\n`;
                        Object.entries(att.internal_parameters).forEach(([key, value]) => {
                            html += `    ${key}: ${value}\n`;
                        });
                        html += '\n';
                    }

                    // Resolved Dependencies
                    if (att.resolved_dependencies && att.resolved_dependencies.length > 0) {
                        html += `  Resolved Dependencies:\n`;
                        att.resolved_dependencies.forEach(dep => {
                            html += `    - ${dep.uri || 'N/A'}\n`;
                            if (dep.digest) {
                                Object.entries(dep.digest).forEach(([alg, hash]) => {
                                    html += `      ${alg}: ${hash}\n`;
                                });
                            }
                        });
                        html += '\n';
                    }

                    // Builder & Run Details
                    if (att.builder || att.metadata) {
                        html += `RUN DETAILS:\n`;

                        if (att.builder) {
                            if (att.builder.id) html += `  Builder ID:      ${att.builder.id}\n`;
                            if (att.builder.version && att.builder.version.commit) {
                                html += `  Builder Commit:  ${att.builder.version.commit}\n`;
                            }
                        }

                        if (att.metadata) {
                            if (att.metadata.invocationID) html += `  Invocation ID:   ${att.metadata.invocationID}\n`;
                            if (att.metadata.startedOn) html += `  Started:         ${att.metadata.startedOn}\n`;
                            if (att.metadata.finishedOn) html += `  Finished:        ${att.metadata.finishedOn}\n`;
                        }
                        html += '\n';
                    }

                    // Verification
                    if (att.verification) {
                        html += `VERIFICATION MATERIAL:\n`;
                        html += `  Certificate:     (length: ${att.verification.certificate_length} chars)\n`;
                        html += `  Transparency Entries: ${att.verification.transparency_entries}\n`;
                        if (att.verification.log_index) {
                            html += `    Log Index:        ${att.verification.log_index}\n`;
                        }
                        if (att.verification.integrated_time) {
                            html += `    Integrated Time:  ${att.verification.integrated_time}\n`;
                        }
                        html += '\n';
                    }
                });

                html += '-'.repeat(80) + '\n\n';
            });

            html += '</div>';
            return html;
        }

        function closeProvenanceModal() {
            const modal = document.getElementById('provenance-modal');
            modal.classList.remove('active');
        }

        // Close modal when clicking outside the content
        document.getElementById('sbom-modal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeSbomModal();
            }
        });

        document.getElementById('files-modal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeFilesModal();
            }
        });

        document.getElementById('provenance-modal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeProvenanceModal();
            }
        });

        // Close modal with Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeSbomModal();
                closeFilesModal();
                closeProvenanceModal();
            }
        });
    </script>
</body>
</html>
"""


async def hello_world(request):
    """Return a nice HTML page showcasing Chainguard Libraries"""
    return web.Response(text=HTML_TEMPLATE, content_type='text/html')


async def health(request):
    """Health check endpoint"""
    return web.json_response({"status": "healthy"})


async def auth_status_handler(request):
    """Return current authentication status"""
    async with auth_lock:
        return web.json_response({
            "authenticated": auth_state["authenticated"],
            "auth_url": auth_state["auth_url"],
            "error": auth_state["error"]
        })


async def chainver_api(request):
    """Return chainver verification results as JSON"""
    # Check if authenticated first
    async with auth_lock:
        if not auth_state["authenticated"]:
            return web.json_response(
                {"error": "Not authenticated with Chainguard. Please authenticate first."},
                status=401
            )

    results = await get_chainver_results()
    return web.json_response(results)


async def chainver_logs_api(request):
    """Return chainver logs (both verbose and normal)"""
    async with logs_lock:
        return web.json_response({
            "verbose": chainver_logs.get("verbose_output", ""),
            "normal": chainver_logs.get("normal_output", ""),
            "last_run": chainver_logs.get("last_run", ""),
            "verbose_last_run": chainver_logs.get("verbose_last_run", "")
        })


async def chainver_verbose_api(request):
    """Run chainver in verbose mode on-demand and return output"""
    global chainver_logs

    # Check if authenticated first
    async with auth_lock:
        if not auth_state["authenticated"]:
            return web.json_response(
                {"error": "Not authenticated with Chainguard. Please authenticate first."},
                status=401
            )

    try:
        wheels_dir = Path('/app/wheels/')
        parent_org = os.environ.get('CHAINVER_PARENT_ORG', '')

        # Get list of wheel files
        wheel_files = sorted(wheels_dir.glob('*.whl'))
        if not wheel_files:
            return web.json_response({"error": "No wheel files found"}, status=404)

        # Build verbose command
        verbose_cmd = ['chainver', '-v', '--detailed']
        if parent_org:
            verbose_cmd.extend(['--parent', parent_org])
        verbose_cmd.extend([str(f) for f in wheel_files])

        # Run chainver in verbose mode
        process = await asyncio.create_subprocess_exec(
            *verbose_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

        # Get current date
        date_process = await asyncio.create_subprocess_exec(
            'date',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        date_stdout, _ = await date_process.communicate()

        # Store verbose output in global state
        async with logs_lock:
            chainver_logs["verbose_output"] = stdout.decode() + "\n\n" + stderr.decode()
            chainver_logs["verbose_last_run"] = date_stdout.decode().strip()

        return web.json_response({
            "verbose": chainver_logs["verbose_output"],
            "last_run": chainver_logs["verbose_last_run"]
        })

    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def get_wheel_contents_api(request):
    """Return the contents of a wheel file as JSON"""
    package_name = request.match_info['package_name']
    version = request.match_info['version']
    contents = get_wheel_contents(package_name, version)
    return web.json_response(contents)


async def get_rekor_hash_handler(request):
    """Get Rekor URL using wheel file SHA256 hash"""
    package_name = request.match_info['package_name']
    version = request.match_info['version']
    hash_data = get_wheel_hash(package_name, version)
    if hash_data:
        return web.json_response(hash_data)
    else:
        return web.json_response(
            {"error": "Could not calculate hash for wheel file"},
            status=404
        )


async def get_pep740_attestations_handler(request):
    """Fetch PEP 740 attestations live from libraries.cgr.dev and check if from Chainguard"""
    package_name = request.match_info['package_name']
    version = request.match_info['version']

    try:
        # Find the wheel filename for the provenance URL
        wheels_dir = Path('/app/wheels/')
        # Convert package name to wheel filename format (hyphens -> underscores)
        wheel_name = package_name.replace('-', '_')
        wheel_pattern = f"{wheel_name}-{version}-*.whl"
        wheel_files = list(wheels_dir.glob(wheel_pattern))

        if not wheel_files:
            return web.json_response({
                "has_attestations": False,
                "error": f"Wheel file not found for {package_name} {version}"
            })

        wheel_filename = wheel_files[0].name

        # Normalize package name for API (PyPI uses hyphens, wheel files use underscores)
        # The libraries.cgr.dev API expects the normalized PyPI package name
        normalized_package_name = package_name.replace('_', '-')

        # Construct the provenance URL
        provenance_url = f"https://libraries.cgr.dev/python/integrity/{normalized_package_name}/{version}/{wheel_filename}/provenance"

        # Try to fetch the provenance data from libraries.cgr.dev
        # Read credentials from .netrc file
        netrc_path = Path.home() / '.netrc'
        username = None
        password = None

        if netrc_path.exists():
            with open(netrc_path, 'r') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    if 'machine libraries.cgr.dev' in line:
                        # Look for login and password in following lines
                        for j in range(i+1, min(i+5, len(lines))):
                            parts = lines[j].strip().split(maxsplit=1)
                            if len(parts) == 2:
                                if parts[0] == 'login':
                                    username = parts[1]
                                elif parts[0] == 'password':
                                    password = parts[1]

        if not username or not password:
            return web.json_response({
                "has_attestations": False,
                "error": "No credentials found in .netrc for libraries.cgr.dev"
            })

        # Fetch provenance data using curl
        process = await asyncio.create_subprocess_exec(
            'curl', '-s', '-u', f'{username}:{password}', provenance_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

        if process.returncode != 0 or not stdout:
            return web.json_response({
                "has_attestations": False,
                "error": "Failed to fetch provenance from libraries.cgr.dev"
            })

        # Parse the provenance data
        try:
            attestation_data = json.loads(stdout.decode())
        except json.JSONDecodeError:
            return web.json_response({
                "has_attestations": False,
                "error": "Invalid provenance data received"
            })

        # Check if this is a Chainguard attestation by looking at publisher info
        is_chainguard = False
        publisher_info = {}

        # Check attestation bundles for Chainguard
        if 'attestation_bundles' in attestation_data:
            for bundle in attestation_data['attestation_bundles']:
                if 'publisher' in bundle:
                    publisher = bundle['publisher']
                    publisher_info = publisher
                    if 'issuer' in publisher:
                        is_chainguard = is_chainguard or 'chainguard' in publisher['issuer'].lower() or 'enforce.dev' in publisher['issuer'].lower()

        return web.json_response({
            "has_attestations": True,
            "is_chainguard": is_chainguard,
            "publisher": publisher_info,
            "provenance_url": provenance_url,
            "wheel_filename": wheel_filename,
            "attestation_count": len(attestation_data.get('attestation_bundles', []))
        })

    except asyncio.TimeoutError:
        return web.json_response({
            "has_attestations": False,
            "error": "Timeout fetching provenance"
        })
    except Exception as e:
        return web.json_response({
            "has_attestations": False,
            "error": str(e)
        })


async def get_parsed_provenance_handler(request):
    """Fetch and parse PEP 740 provenance data in human-readable format"""
    package_name = request.match_info['package_name']
    version = request.match_info['version']

    try:
        # Find the wheel filename for the provenance URL
        wheels_dir = Path('/app/wheels/')
        # Convert package name to wheel filename format (hyphens -> underscores)
        wheel_name = package_name.replace('-', '_')
        wheel_pattern = f"{wheel_name}-{version}-*.whl"
        wheel_files = list(wheels_dir.glob(wheel_pattern))

        if not wheel_files:
            return web.json_response({
                "error": f"Wheel file not found for {package_name} {version}"
            }, status=404)

        wheel_filename = wheel_files[0].name

        # Normalize package name for API (PyPI uses hyphens, wheel files use underscores)
        # The libraries.cgr.dev API expects the normalized PyPI package name
        normalized_package_name = package_name.replace('_', '-')

        # Construct the provenance URL
        provenance_url = f"https://libraries.cgr.dev/python/integrity/{normalized_package_name}/{version}/{wheel_filename}/provenance"

        # Read credentials from .netrc file
        netrc_path = Path.home() / '.netrc'
        username = None
        password = None

        if netrc_path.exists():
            with open(netrc_path, 'r') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    if 'machine libraries.cgr.dev' in line:
                        for j in range(i+1, min(i+5, len(lines))):
                            parts = lines[j].strip().split(maxsplit=1)
                            if len(parts) == 2:
                                if parts[0] == 'login':
                                    username = parts[1]
                                elif parts[0] == 'password':
                                    password = parts[1]

        if not username or not password:
            return web.json_response({
                "error": "No credentials found in .netrc for libraries.cgr.dev"
            }, status=401)

        # Fetch provenance data
        process = await asyncio.create_subprocess_exec(
            'curl', '-s', '-u', f'{username}:{password}', provenance_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)

        if process.returncode != 0 or not stdout:
            return web.json_response({
                "error": "Failed to fetch provenance from libraries.cgr.dev"
            }, status=500)

        # Parse the provenance data
        try:
            provenance_data = json.loads(stdout.decode())
        except json.JSONDecodeError:
            return web.json_response({
                "error": "Invalid provenance data received"
            }, status=500)

        # Parse and format the provenance data similar to parse-provenance.py
        parsed_result = parse_provenance_data(provenance_data)
        parsed_result['provenance_url'] = provenance_url
        parsed_result['wheel_filename'] = wheel_filename

        return web.json_response(parsed_result)

    except asyncio.TimeoutError:
        return web.json_response({
            "error": "Timeout fetching provenance"
        }, status=500)
    except Exception as e:
        return web.json_response({
            "error": str(e)
        }, status=500)


def parse_provenance_data(provenance_data):
    """Parse provenance data into a structured format"""
    result = {
        "version": provenance_data.get('version', 1),
        "bundles": []
    }

    for bundle in provenance_data.get('attestation_bundles', []):
        bundle_info = {
            "publisher": bundle.get('publisher', {}),
            "attestations": []
        }

        for attestation in bundle.get('attestations', []):
            att_info = {
                "version": attestation.get('version', 1)
            }

            # Decode the statement
            envelope = attestation.get('envelope', {})
            if 'statement' in envelope:
                import base64
                statement_bytes = base64.b64decode(envelope['statement'])
                statement = json.loads(statement_bytes.decode('utf-8'))

                # Extract key information
                att_info['subject'] = statement.get('subject', [])

                predicate = statement.get('predicate', {})
                build_def = predicate.get('buildDefinition', {})

                att_info['build_type'] = build_def.get('buildType', '')
                att_info['external_parameters'] = build_def.get('externalParameters', {})
                att_info['internal_parameters'] = build_def.get('internalParameters', {})
                att_info['resolved_dependencies'] = build_def.get('resolvedDependencies', [])

                run_details = predicate.get('runDetails', {})
                att_info['builder'] = run_details.get('builder', {})
                att_info['metadata'] = run_details.get('metadata', {})

            # Verification material
            verif_material = attestation.get('verification_material', {})
            if verif_material:
                att_info['verification'] = {
                    'certificate_length': len(verif_material.get('certificate', '')),
                    'transparency_entries': len(verif_material.get('transparency_entries', []))
                }

                # Get first transparency entry details
                if verif_material.get('transparency_entries'):
                    entry = verif_material['transparency_entries'][0]
                    att_info['verification']['log_index'] = entry.get('logIndex', '')
                    att_info['verification']['integrated_time'] = entry.get('integratedTime', '')

            bundle_info['attestations'].append(att_info)

        result['bundles'].append(bundle_info)

    return result


async def get_sbom_handler(request):
    """Serve the PEP 770 SBOM file for a given package with resolved commit SHA"""
    package_name = request.match_info['package_name']

    try:
        site_packages = Path('/usr/lib/python3.11/site-packages/')

        # Find the package's dist-info directory
        dist_info_dirs = list(site_packages.glob(f"{package_name}-*.dist-info"))

        if not dist_info_dirs:
            return web.json_response(
                {"error": f"Package {package_name} not found"},
                status=404
            )

        # Get the SBOM file from the first matching dist-info directory
        sbom_path = dist_info_dirs[0] / 'sboms' / 'sbom.spdx.json'

        if not sbom_path.exists():
            return web.json_response(
                {"error": f"SBOM not found for {package_name}"},
                status=404
            )

        # Read and return the SBOM as JSON
        with open(sbom_path, 'r') as f:
            sbom_data = json.load(f)

        # Find and parse sourceInfo to resolve tag object to commit
        # Look for sourceInfo in packages
        if 'packages' in sbom_data:
            for package in sbom_data['packages']:
                if 'sourceInfo' in package:
                    source_info = package['sourceInfo']
                    # Parse sourceInfo
                    match = re.search(
                        r'git\+(https?://[^\s,]+).*?tag:\s*([^,\s]+).*?commit\s+id:\s*([a-f0-9]{40})',
                        source_info,
                        re.IGNORECASE
                    )
                    if match:
                        repo_url = match.group(1)
                        tag_name = match.group(2)
                        object_id = match.group(3)

                        # Resolve the tag object to actual commit SHA
                        resolved_commit = await resolve_tag_to_commit(repo_url, tag_name, object_id)

                        # Add the resolved commit SHA to the package data
                        package['_resolved_commit_sha'] = resolved_commit

        return web.json_response(sbom_data)

    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


def extract_sbom_provenance(package_name, version):
    """Extract key provenance information from PEP 770 SBOM"""
    try:
        site_packages = Path('/usr/lib/python3.11/site-packages/')

        # Find the package's dist-info directory
        dist_info_dirs = list(site_packages.glob(f"{package_name}-*.dist-info"))

        if not dist_info_dirs:
            return None

        sbom_path = dist_info_dirs[0] / 'sboms' / 'sbom.spdx.json'

        if not sbom_path.exists():
            return None

        with open(sbom_path, 'r') as f:
            sbom_data = json.load(f)

        # Extract key information
        provenance = {
            "has_sbom": True,
            "creator": None,
            "created": None,
            "patches": [],
            "source_repo": None,
            "commit_id": None
        }

        # Get creator information
        if 'creationInfo' in sbom_data and 'creators' in sbom_data['creationInfo']:
            creators = sbom_data['creationInfo']['creators']
            provenance['creator'] = ', '.join(creators)
            provenance['created'] = sbom_data['creationInfo'].get('created', '')

        # Get package information and patches
        if 'packages' in sbom_data:
            for package in sbom_data['packages']:
                if package.get('name') == package_name:
                    # Extract source info with patches
                    source_info = package.get('sourceInfo', '')

                    # Parse patches from sourceInfo
                    if 'patches:' in source_info:
                        patches_text = source_info.split('patches:')[1]
                        patches = [p.strip() for p in patches_text.split(',') if p.strip()]
                        provenance['patches'] = patches

                    # Extract source repo and commit
                    if 'downloadLocation' in package:
                        download_loc = package['downloadLocation']
                        if 'git+' in download_loc:
                            # Extract repo URL and commit
                            match = re.search(r'git\+(https?://[^@]+)@([a-f0-9]{40})', download_loc)
                            if match:
                                provenance['source_repo'] = match.group(1)
                                provenance['commit_id'] = match.group(2)

                    break

        return provenance

    except Exception as e:
        print(f"Error extracting SBOM provenance for {package_name}: {e}")
        return None


async def get_sbom_provenance_api(request):
    """Return SBOM provenance data for all installed packages"""
    try:
        import pkg_resources

        packages = []
        for dist in pkg_resources.working_set:
            package_name = dist.project_name
            version = dist.version

            # Skip pip and setuptools
            if package_name in ['pip', 'setuptools']:
                continue

            provenance = extract_sbom_provenance(package_name, version)

            packages.append({
                "name": package_name,
                "version": version,
                "provenance": provenance
            })

        return web.json_response({"packages": packages})

    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


def setup_routes(app):
    """Setup all application routes"""
    app.router.add_get('/', hello_world)
    app.router.add_get('/health', health)
    app.router.add_get('/api/auth/status', auth_status_handler)
    app.router.add_get('/api/chainver', chainver_api)
    app.router.add_get('/api/chainver/logs', chainver_logs_api)
    app.router.add_get('/api/chainver/verbose', chainver_verbose_api)
    app.router.add_get('/api/wheel-contents/{package_name}/{version}', get_wheel_contents_api)
    app.router.add_get('/api/rekor-hash/{package_name}/{version}', get_rekor_hash_handler)
    app.router.add_get('/api/pep740-attestations/{package_name}/{version}', get_pep740_attestations_handler)
    app.router.add_get('/api/provenance/{package_name}/{version}', get_parsed_provenance_handler)
    app.router.add_get('/api/sbom/{package_name}', get_sbom_handler)

    # Static file serving using aiohttp's built-in handler
    # VULNERABLE in aiohttp 3.9.0 (GHSA-5h86-8mv2-jq9f) when follow_symlinks=True
    # The vulnerability allows path traversal to read arbitrary files when this flag is set
    # FIXED in aiohttp 3.9.2+ - properly validates paths even with follow_symlinks=True
    static_dir = Path(__file__).parent / 'static'
    app.router.add_static('/static', static_dir, follow_symlinks=True, name='static')


async def on_startup(app):
    """Start authentication flow on application startup"""
    print("Starting Chainguard authentication flow...")
    await start_headless_auth()


def main():
    """Main entry point"""
    app = web.Application()
    setup_routes(app)
    app.on_startup.append(on_startup)

    # Run the app on all interfaces, port 5000
    web.run_app(app, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()
