import sys

# TXT mode is independent of the optional dependencies used by legacy web checks.
if __name__ == "__main__" and "--txt" in sys.argv[1:]:
    from txt_enum import main as txt_main

    raise SystemExit(txt_main([arg for arg in sys.argv[1:] if arg != "--txt"]))

import concurrent.futures
import argparse
import os
import json
import logging
import csv
import yaml
from datetime import datetime
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from modules.dns_utils import (
    load_dns_integrations,
    dns_check,
    check_dns_providers,
)
from modules.reporting import display_results, console

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def select_providers(integrations, providers):
    if providers is None:
        return integrations
    names = {name.casefold(): name for name in integrations}
    requested = [name.strip().casefold() for name in providers]
    unknown = [name for name in requested if name not in names]
    if not requested or unknown:
        raise ValueError("Unknown or empty provider selection: " + ", ".join(unknown))
    return {names[name]: integrations[names[name]] for name in requested}


def run_checks(
    short_name,
    providers=None,
    max_workers=10,
    output_json=False,
    verbose=False,
    output_file=None,
    format="text",
    timeout=20,
    yaml_path=None,
):
    """
    Run checks for the given short_name against all or specified providers.
    """
    results = []

    # Load the DNS integrations
    DNS_INTEGRATIONS = load_dns_integrations(yaml_path)

    integrations_to_check = select_providers(DNS_INTEGRATIONS, providers)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Checking {len(integrations_to_check)} providers for '{short_name}'...",
            total=len(integrations_to_check),
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create future to provider mapping
            futures_dict = {}
            for provider, domain_template in integrations_to_check.items():
                future = executor.submit(
                    dns_check, provider, domain_template, short_name, timeout
                )
                futures_dict[future] = provider

            # Use wait() instead of as_completed() for better control
            remaining_futures = set(futures_dict.keys())

            while remaining_futures:
                # Wait for some futures to complete, with a reasonable timeout
                done, not_done = concurrent.futures.wait(
                    remaining_futures,
                    timeout=10.0,  # Wait up to 10 seconds for completions
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )

                # Process completed futures
                for future in done:
                    provider = futures_dict[future]
                    try:
                        result = future.result(
                            timeout=0.1
                        )  # Should be immediate since it's done
                        results.append(result)
                    except concurrent.futures.TimeoutError:
                        logger.warning(
                            f"Unexpected timeout getting result for {provider}"
                        )
                        timeout_result = {
                            "provider": provider,
                            "hostname": integrations_to_check[provider].replace(
                                "SHORT_NAME", short_name
                            ),
                            "status": "timeout",
                            "message": f"Result retrieval timed out",
                            "dns_result": None,
                            "web_check": {
                                "performed": False,
                                "details": "Result timeout",
                            },
                        }
                        results.append(timeout_result)
                    except Exception as e:
                        logger.error(
                            f"Error processing result for {provider}: {str(e)}"
                        )
                        error_result = {
                            "provider": provider,
                            "hostname": integrations_to_check[provider].replace(
                                "SHORT_NAME", short_name
                            ),
                            "status": "error",
                            "message": f"Error: {str(e)}",
                            "dns_result": None,
                            "web_check": {
                                "performed": False,
                                "details": f"Error: {str(e)}",
                            },
                        }
                        results.append(error_result)

                    progress.update(task, advance=1)

                # Remove completed futures from remaining set
                remaining_futures -= done

                # If no futures completed in this round and we still have some left,
                # check if any are taking too long
                if not done and not_done:
                    logger.warning(
                        f"No futures completed in this round. {len(not_done)} still running."
                    )

                    # Force timeout on futures that have been running too long
                    for future in list(not_done):
                        try:
                            # Try to get result with very short timeout
                            result = future.result(timeout=0.1)
                            provider = futures_dict[future]
                            results.append(result)
                            progress.update(task, advance=1)
                            remaining_futures.discard(future)
                        except concurrent.futures.TimeoutError:
                            # Still running, let it continue
                            continue
                        except Exception as e:
                            # Handle other errors
                            provider = futures_dict[future]
                            logger.error(f"Error with future for {provider}: {str(e)}")
                            error_result = {
                                "provider": provider,
                                "hostname": integrations_to_check[provider].replace(
                                    "SHORT_NAME", short_name
                                ),
                                "status": "error",
                                "message": f"Future error: {str(e)}",
                                "dns_result": None,
                                "web_check": {
                                    "performed": False,
                                    "details": f"Future error: {str(e)}",
                                },
                            }
                            results.append(error_result)
                            progress.update(task, advance=1)
                            remaining_futures.discard(future)

            # This should not happen anymore, but just in case
            if remaining_futures:
                logger.warning(
                    f"Forcing completion for {len(remaining_futures)} remaining futures"
                )
                for future in remaining_futures:
                    provider = futures_dict[future]
                    future.cancel()
                    timeout_result = {
                        "provider": provider,
                        "hostname": integrations_to_check[provider].replace(
                            "SHORT_NAME", short_name
                        ),
                        "status": "cancelled",
                        "message": f"Future was cancelled",
                        "dns_result": None,
                        "web_check": {"performed": False, "details": "Cancelled"},
                    }
                    results.append(timeout_result)
                    progress.update(task, advance=1)

    # Sort results by status priority
    def sort_key(x):
        status_priority = {
            "confirmed_valid": 0,
            "confirmed_via_web": 1,
            "url_only_match": 2,
            "valid_dns": 3,
            "dns_only_match": 4,
            "wildcard_match": 5,
            "no_record": 6,
            "timeout": 7,
            "error": 8,
        }

        priority = status_priority.get(x["status"], 9)
        return priority

    results.sort(key=sort_key)

    # Handle different output formats
    if format == "json" or output_json:
        if output_file:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]Results saved to {output_file}[/green]")
        else:
            print(json.dumps(results, indent=2))
    elif format == "csv" and output_file:
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Provider", "Hostname", "Status", "URL", "Details"])
            for result in results:
                writer.writerow(
                    [
                        result["provider"],
                        result["hostname"],
                        result["status"],
                        result["web_check"].get("final_url", ""),
                        result["web_check"].get("details", ""),
                    ]
                )
        console.print(f"[green]Results saved to {output_file}[/green]")
    else:
        # Display results in console with rich formatting
        display_results(results, short_name, verbose)

        # Save to text file if specified
        if output_file and format == "text":
            with open(output_file, "w") as f:
                f.write(f"SaaS Provider Detection Results for '{short_name}'\n")
                f.write(
                    f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                )

                confirmed_count = sum(
                    1
                    for r in results
                    if r["status"] in ["confirmed_valid", "confirmed_via_web"]
                )
                possible_count = sum(
                    1
                    for r in results
                    if r["status"] in ["url_only_match", "valid_dns", "dns_only_match"]
                )

                f.write(f"Summary:\n")
                f.write(f"  Corroborated associations: {confirmed_count}\n")
                f.write(f"  Possible integrations: {possible_count}\n")
                f.write(f"  Total checked: {len(results)}\n  Active service use is not verified.\n\n")

                f.write("Detailed Results:\n")
                for result in results:
                    status = result["status"]

                    if status in ["confirmed_valid", "confirmed_via_web"]:
                        prefix = "[+]"
                    elif status in ["url_only_match", "valid_dns", "dns_only_match"]:
                        prefix = "[?]"
                    elif status == "wildcard_match":
                        prefix = "[!]"
                    else:
                        if not verbose:
                            continue
                        prefix = "[-]"

                    f.write(
                        f"{prefix} {result['provider']}: {result['hostname']} - {result['message']}\n"
                    )

                    if verbose or status in [
                        "confirmed_valid",
                        "confirmed_via_web",
                        "url_only_match",
                        "dns_only_match",
                    ]:
                        if result["web_check"]["performed"]:
                            f.write(
                                f"    URL: {result['web_check']['url_checked']} → {result['web_check']['final_url']}\n"
                            )
                            if result["web_check"]["page_title"]:
                                f.write(
                                    f"    Page Title: {result['web_check']['page_title']}\n"
                                )
                            if result["web_check"]["details"]:
                                f.write(
                                    f"    Details: {result['web_check']['details']}\n"
                                )
                            if result["web_check"].get("match_strength"):
                                f.write(
                                    f"    Match Strength: {result['web_check']['match_strength']}\n"
                                )

                            if result["web_check"]["text_snippets"]:
                                f.write("    Text Snippets:\n")
                                for i, snippet in enumerate(
                                    result["web_check"]["text_snippets"][:3], 1
                                ):
                                    f.write(f"      {i}. {snippet}\n")
                            f.write("\n")

            console.print(f"[green]Results saved to {output_file}[/green]")

    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Enhanced SaaS Provider Detection Tool",
        epilog="TXT-only mode: python saas_enum.py --txt --domain example.com (or --txt --help)",
    )
    parser.add_argument("-i", "--input", help="SHORT_NAME to use in lookup")
    parser.add_argument(
        "-j", "--json", action="store_true", help="Output results in JSON format"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed output for all checks",
    )
    parser.add_argument(
        "-p", "--providers", help="Comma-separated list of specific providers to check"
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Maximum number of concurrent workers",
    )
    parser.add_argument(
        "-l",
        "--list-providers",
        action="store_true",
        help="List all available providers and exit",
    )
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "-b",
        "--batch",
        help="File containing multiple SHORT_NAMEs to check (one per line)",
    )
    parser.add_argument(
        "-c",
        "--check-providers",
        action="store_true",
        help="Check providers for wildcard DNS",
    )
    parser.add_argument(
        "-y",
        "--yaml",
        default=None,
        help="Provider YAML file (defaults to dns_integrations.yaml beside the script)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=20,
        help="Timeout in seconds for each provider check",
    )
    args = parser.parse_args(argv)

    # Validate the selected catalog and provider scope before any network requests.
    try:
        DNS_INTEGRATIONS = load_dns_integrations(args.yaml)
        requested = args.providers.split(",") if args.providers is not None else None
        selected_providers = list(select_providers(DNS_INTEGRATIONS, requested))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))

    if args.list_providers:
        console.print("[bold]Available providers:[/bold]")
        table = Table()
        table.add_column("#", style="cyan")
        table.add_column("Provider", style="green")
        table.add_column("Domain Template", style="blue")

        for idx, (provider, template) in enumerate(sorted(DNS_INTEGRATIONS.items()), 1):
            table.add_row(str(idx), provider, template)

        console.print(table)
        return

    # Check providers for wildcard DNS
    if args.check_providers:
        check_dns_providers(args.yaml)
        return

    # Batch processing
    if args.batch:
        if not os.path.exists(args.batch):
            console.print(
                f"[bold red]Error:[/bold red] Batch file not found: {args.batch}"
            )
            return

        with open(args.batch, "r") as f:
            short_names = [line.strip() for line in f if line.strip()]

        console.print(
            f"[bold]Processing {len(short_names)} company names from batch file...[/bold]"
        )

        batch_results = {}
        for name in short_names:
            console.print(f"\n[bold]Checking: {name}[/bold]")
            results = run_checks(
                short_name=name,
                providers=selected_providers,
                max_workers=args.workers,
                output_json=False,
                verbose=args.verbose,
                timeout=args.timeout,
                yaml_path=args.yaml,
            )
            batch_results[name] = results

        # Save batch results if output file specified
        if args.output:
            if args.format == "json":
                with open(args.output, "w") as f:
                    json.dump(batch_results, f, indent=2)
            elif args.format == "csv":
                with open(args.output, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(
                        ["Company", "Provider", "Hostname", "Status", "URL"]
                    )

                    for company, results in batch_results.items():
                        for result in results:
                            writer.writerow(
                                [
                                    company,
                                    result["provider"],
                                    result["hostname"],
                                    result["status"],
                                    result["web_check"].get("final_url", ""),
                                ]
                            )
            else:
                with open(args.output, "w") as f:
                    f.write(f"SaaS Provider Detection Batch Results\n")
                    f.write(
                        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    )

                    for company, results in batch_results.items():
                        f.write(f"== Results for '{company}' ==\n")
                        confirmed_count = sum(
                            1
                            for r in results
                            if r["status"] in ["confirmed_valid", "confirmed_via_web"]
                        )
                        possible_count = sum(
                            1
                            for r in results
                            if r["status"] in ["valid_dns", "dns_only_match"]
                        )

                        f.write(f"  Corroborated associations: {confirmed_count}\n")
                        f.write(f"  Possible integrations: {possible_count}\n")
                        f.write(f"  Total checked: {len(results)}\n  Active service use is not verified.\n\n")

            console.print(f"[green]Batch results saved to {args.output}[/green]")

        return

    # Single company check
    if args.input:
        short_name = args.input.strip()
        run_checks(
            short_name=short_name,
            providers=selected_providers,
            max_workers=args.workers,
            output_json=args.json,
            verbose=args.verbose,
            output_file=args.output,
            format=args.format,
            timeout=args.timeout,
            yaml_path=args.yaml,
        )
    else:
        console.print(
            "[bold yellow]Error:[/bold yellow] No input provided. Use --input or --batch to specify company names to check."
        )
        console.print("Use --help for more information.")


if __name__ == "__main__":
    main()
