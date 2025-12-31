# Copyright 2025 Aegis Security
#
# The Main CLI Entry Point.
# Orchestrates: Config -> Scan -> Verify -> Sign.

import sys
import typer
import logging
import json
import os
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# --- Internal Modules ---
from aegis.core.config import ConfigLoader
from aegis.core.types import ScanResult, Severity
from aegis.engines.hashing.calculator import calculate_sha256
from aegis.engines.static.pickle_engine import scan_pickle_stream
from aegis.engines.static.keras_engine import scan_keras_file
from aegis.integrations.cosign import sign_container, is_cosign_available

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("aegis")

# Setup Typer & Rich
app = typer.Typer(help="Aegis: AI Model Security Scanner & Gatekeeper")
console = Console()

# Supported Extensions
PICKLE_EXTS = {".pt", ".pth", ".bin", ".pkl", ".ckpt"}
KERAS_EXTS = {".h5", ".keras"}
SAFETENSORS_EXTS = {".safetensors"}
GGUF_EXTS = {".gguf"}

@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to model file or directory"),
    image: Optional[str] = typer.Option(None, help="Docker image tag to sign (e.g. myrepo/model:v1)"),
    force: bool = typer.Option(False, "--force", "-f", help="Break-glass: Force approval even if risks found"),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed logs"),
):
    """
    Scans a model for malware, verifies integrity, and optionally signs the container.
    """
    # 1. Load Configuration
    config = ConfigLoader.load()
    if verbose:
        logger.setLevel(logging.DEBUG)
        console.print(f"[dim]Loaded config from {path}[/dim]")

    if not json_output:
        console.print(Panel.fit(f"🛡️  [bold cyan]Aegis Security Scanner[/bold cyan] v4.1", border_style="cyan"))

    # 2. Collect Files
    files_to_scan = []
    if path.is_file():
        files_to_scan.append(path)
    elif path.is_dir():
        files_to_scan.extend([p for p in path.rglob("*") if p.is_file()])
    else:
        console.print(f"[bold red]Error:[/bold red] Path {path} not found.")
        raise typer.Exit(code=1)

    # 3. Execution Loop
    results: List[ScanResult] = []
    has_critical_errors = False

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        disable=json_output # Disable progress bar if JSON output is requested
    ) as progress:
        
        task = progress.add_task(f"Scanning {len(files_to_scan)} files...", total=len(files_to_scan))

        for file_path in files_to_scan:
            ext = file_path.suffix.lower()
            progress.update(task, description=f"Analyzing {file_path.name}...")
            
            # Initialize Result Object
            scan_res = ScanResult(file_path=str(file_path.name))

            # --- A. Identity (Hashing) ---
            try:
                # Calculate SHA256 (handles LFS pointers automatically via calculator.py)
                file_hash = calculate_sha256(file_path)
                scan_res.file_hash = file_hash
                
                # TODO (Sprint 2): Call HuggingFace API to verify hash identity
                # from aegis.integrations.huggingface import HuggingFaceClient
                # hf_client = HuggingFaceClient(token=config.hf_token)
                # verification = hf_client.verify_file_hash(repo_id, file_path.name, file_hash)
                # if verification == "MISMATCH":
                #     scan_res.add_threat("CRITICAL: Hash mismatch with Hugging Face registry")

            except Exception as e:
                scan_res.add_threat(f"Hashing Error: {str(e)}")

            # --- B. Static Analysis ---
            threats = []
            
            # 1. Pickle / PyTorch
            if ext in PICKLE_EXTS:
                try:
                    with open(file_path, "rb") as f:
                        # For MVP simplicity, we read the raw stream. 
                        # In production, use readers.py to extract pickle from zip if needed.
                        content = f.read() 
                        threats = scan_pickle_stream(content, strict_mode=True)
                except Exception as e:
                    threats.append(f"Scan Error: {str(e)}")

            # 2. Keras / H5
            elif ext in KERAS_EXTS:
                threats = scan_keras_file(file_path)

            # 3. Safetensors / GGUF (Generally Safe, check metadata)
            elif ext in SAFETENSORS_EXTS or ext in GGUF_EXTS:
                # TODO: Check for license violations in metadata via readers.py
                pass

            # --- C. Policy Check ---
            if threats:
                for t in threats:
                    scan_res.add_threat(t)
                has_critical_errors = True
            
            results.append(scan_res)
            progress.advance(task)

    # 4. Reporting
    if json_output:
        # Serialize objects to dicts
        results_dicts = [r.__dict__ for r in results]
        console.print_json(json.dumps(results_dicts))
    else:
        _print_table(results)

    # 5. Decision & Action
    sign_status = "clean"
    
    if has_critical_errors:
        if force:
            if not json_output:
                console.print("\n[bold yellow]⚠️  CRITICAL RISKS DETECTED[/bold yellow]")
                console.print(f"[yellow]Break-glass mode enabled (--force). Proceeding with caution.[/yellow]")
            # Add annotation to signature
            sign_status = "forced_approval"
        else:
            if not json_output:
                console.print("\n[bold red]❌ BLOCKING DEPLOYMENT[/bold red]")
                console.print("Critical threats detected. Use --force to override if authorized.")
            raise typer.Exit(code=1)
    else:
        if not json_output:
            console.print("\n[bold green]✅ Scan Passed. Model is clean.[/bold green]")

    # 6. Signing (Sprint 4)
    if image:
        _perform_signing(image, sign_status, config)


def _print_table(results: List[ScanResult]):
    """Renders a pretty table of results."""
    table = Table(title="Scan Results")
    table.add_column("File", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Threats / Details", style="magenta")
    table.add_column("SHA256 (Short)", style="dim")

    for res in results:
        status_style = "green" if res.status == "PASS" else "bold red"
        threat_text = "\n".join(res.threats) if res.threats else "None"
        short_hash = res.file_hash[:8] + "..." if res.file_hash else "N/A"
        
        table.add_row(
            res.file_path,
            f"[{status_style}]{res.status}[/{status_style}]",
            threat_text,
            short_hash
        )
    console.print(table)


def _perform_signing(image: str, status: str, config):
    """
    Wrapper for Cosign integration.
    """
    console.print(f"\n🔐 [bold]Signing container:[/bold] {image}")
    
    # Determine key path (Config -> Env -> Default)
    key_path = config.private_key_path
    if not key_path and "AEGIS_PRIVATE_KEY_PATH" in os.environ:
        key_path = os.environ["AEGIS_PRIVATE_KEY_PATH"]
    
    if not key_path:
         console.print("[red]Skipping signing: No private key found (set AEGIS_PRIVATE_KEY_PATH).[/red]")
         return

    success = sign_container(
        image_ref=image, 
        key_path=key_path, 
        annotations={"scanned_by": "aegis", "status": status}
    )

    if success:
        console.print(f"[green]✔ Signed successfully with status: {status}[/green]")
        console.print(f"[dim]Artifact pushed to OCI registry.[/dim]")
    else:
        console.print(f"[bold red]Signing Failed.[/bold red] Check logs for details.")
        # We don't fail the build if signing fails, unless strict mode is on (future feature)


@app.command()
def keygen(output_prefix: str = "aegis"):
    """
    Generates a generic Cosign key pair for signing.
    """
    console.print(f"[bold]Generating Cosign Key Pair ({output_prefix})...[/bold]")
    
    if not is_cosign_available():
        console.print("[bold red]Error:[/bold red] 'cosign' binary not found in PATH.")
        raise typer.Exit(code=1)

    # We call the integration function (assuming it exists in cosign.py as discussed)
    # If not implemented yet, we print instructions.
    try:
        from aegis.integrations.cosign import generate_key_pair
        if generate_key_pair(output_prefix):
            console.print(f"[green]✔ Keys generated: {output_prefix}.key / {output_prefix}.pub[/green]")
            console.print(f"Set [cyan]AEGIS_PRIVATE_KEY_PATH={output_prefix}.key[/cyan] to use them.")
        else:
            console.print("[red]Key generation failed.[/red]")
    except ImportError:
        console.print("Run: [green]cosign generate-key-pair[/green]")


@app.command()
def version():
    """Show version info."""
    console.print("Aegis v4.1 (Enterprise Edition)")


if __name__ == "__main__":
    app()
