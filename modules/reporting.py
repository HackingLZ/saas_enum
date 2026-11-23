from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def display_results(results, short_name, verbose):
    """Display results in a nicely formatted table using Rich"""
    confirmed_count = sum(1 for r in results if r["status"] in ["confirmed_valid", "confirmed_via_web"])
    possible_count = sum(1 for r in results if r["status"] in ["url_only_match", "valid_dns", "dns_only_match"])

    summary = Table(title=f"SaaS Provider Detection Results for '{short_name}'")
    summary.add_column("Category", style="cyan")
    summary.add_column("Count", style="green")

    summary.add_row("Corroborated Associations", str(confirmed_count))
    summary.add_row("Possible Integrations", str(possible_count))
    summary.add_row("Total Checked", str(len(results)))

    console.print(summary)
    console.print("[dim]Corroborated associations are evidence of a tenant-specific page, not verified active use.[/dim]")
    console.print()

    table = Table(title="Detailed Results")
    table.add_column("Status", style="bold")
    table.add_column("Provider", style="cyan")
    table.add_column("Hostname")
    table.add_column("Notes")

    for result in results:
        status = result["status"]

        if status in ["confirmed_valid", "confirmed_via_web"]:
            status_str = "✅ CORROBORATED"
            status_style = "green"
        elif status == "url_only_match":
            status_str = "🔍 URL ONLY"
            status_style = "yellow"
        elif status in ["valid_dns", "dns_only_match"]:
            status_str = "❓ POSSIBLE"
            status_style = "yellow"
        elif status == "wildcard_match":
            status_str = "⚠️ WILDCARD"
            status_style = "red"
        else:
            if not verbose:
                continue
            status_str = "❌ NOT FOUND"
            status_style = "dim"

        table.add_row(
            f"[{status_style}]{status_str}[/{status_style}]",
            result["provider"],
            result["hostname"],
            result["message"],
        )

    console.print(table)

    for result in results:
        status = result["status"]
        if verbose or status in ["confirmed_valid", "confirmed_via_web", "url_only_match", "dns_only_match"]:
            if result["web_check"]["performed"] and (result["web_check"]["reference_found"] or verbose):
                match_strength = result["web_check"].get("match_strength", "unknown")
                panel_title = f"{result['provider']}: {result['hostname']} ({match_strength} evidence)"

                if status in ["confirmed_valid", "confirmed_via_web"]:
                    panel_style = "green"
                elif status == "url_only_match":
                    panel_style = "yellow"
                elif status in ["dns_only_match", "valid_dns"]:
                    panel_style = "yellow"
                else:
                    panel_style = "red"

                content = []

                if result["web_check"]["final_url"]:
                    content.append(f"[bold]URL:[/bold] {result['web_check']['url_checked']} → {result['web_check']['final_url']}")

                if result["web_check"]["page_title"]:
                    content.append(f"[bold]Page Title:[/bold] {result['web_check']['page_title']}")

                if result["web_check"]["details"]:
                    content.append(f"[bold]Analysis:[/bold] {result['web_check']['details']}")

                if "evidence" in result["web_check"] and result["web_check"]["evidence"]:
                    content.append(f"[bold]Evidence:[/bold] {', '.join(result['web_check']['evidence'][:5])}")

                if result["web_check"]["text_snippets"]:
                    content.append("[bold]Text Snippets:[/bold]")
                    for i, snippet in enumerate(result["web_check"]["text_snippets"][:3], 1):
                        content.append(f"  {i}. {snippet}")

                if content:
                    panel = Panel("\n".join(content), title=panel_title, border_style=panel_style)
                    console.print(panel)
