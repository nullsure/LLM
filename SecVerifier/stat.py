#!/usr/bin/env python3

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table


@dataclass
class ComponentResult:
    success: bool = False


@dataclass
class TestResult:
    builder: ComponentResult = field(default_factory=ComponentResult)
    exploiter: ComponentResult = field(default_factory=ComponentResult)
    fixer: ComponentResult = field(default_factory=ComponentResult)


@dataclass
class AnalysisResult:
    instance_id: str
    project_name: str
    test_result: TestResult
    steps: int
    cost: Optional[float]


def parse_args():
    parser = argparse.ArgumentParser(description='Analyze results from input file')
    parser.add_argument(
        '--input-file', required=True, help='Input file to analyze (JSONL format)'
    )
    return parser.parse_args()


def extract_project_name(instance_id: str) -> str:
    """Extract project name from instance ID."""
    # Assuming instance_id format is "project_name-something-else"
    # Modify this function based on your actual instance_id format
    parts = instance_id.split('-')
    if parts:
        return parts[0]
    return 'unknown'


def analyze_instance(instance: Dict[str, Any]) -> AnalysisResult:
    instance_id = instance.get('instance_id', 'N/A')
    project_name = extract_project_name(instance_id)

    # Extract test results
    test_result_data = instance.get('test_result', {})

    # Create component results
    builder = ComponentResult(
        success=test_result_data.get('execution', {})
        .get('builder', {})
        .get('success', False)
    )
    exploiter = ComponentResult(
        success=test_result_data.get('execution', {})
        .get('exploiter', {})
        .get('success', False)
    )
    fixer = ComponentResult(
        success=test_result_data.get('execution', {})
        .get('fixer', {})
        .get('success', False)
    )

    test_result = TestResult(builder=builder, exploiter=exploiter, fixer=fixer)

    # Count steps where source is 'agent'
    history = instance.get('history', [])
    agent_steps = sum(1 for item in history if item.get('source') == 'agent') / 2

    # Get metrics
    metrics = instance.get('metrics', {})
    accumulated_cost = metrics.get('accumulated_cost', None) / 2

    return AnalysisResult(
        instance_id=instance_id,
        project_name=project_name,
        test_result=test_result,
        steps=int(agent_steps),
        cost=accumulated_cost,
    )


def format_boolean(value: bool) -> str:
    """Format boolean values as emoji."""
    return '✅' if value else '❌'


def calculate_statistics(results: List[AnalysisResult]) -> Dict[str, Any]:
    """Calculate statistics based on analysis results."""
    total = len(results)
    if total == 0:
        return {
            'builder_success_rate': 0,
            'exploiter_success_rate': 0,
            'fixer_success_rate': 0,
            'avg_cost': 0,
            'avg_steps': 0,
            'total_cost': 0,
        }

    builder_success = sum(1 for r in results if r.test_result.builder.success)
    exploiter_success = sum(1 for r in results if r.test_result.exploiter.success)
    fixer_success = sum(1 for r in results if r.test_result.fixer.success)

    # Filter out None costs before calculating average
    costs = [r.cost for r in results if r.cost is not None]
    total_cost = sum(costs) if costs else 0
    avg_cost = total_cost / len(costs) if costs else 0

    avg_steps = sum(r.steps for r in results) / total

    # Prepare success rate strings with safe division
    builder_rate = (
        f'{builder_success}/{total} ({builder_success / total * 100:.1f}%)'
        if total > 0
        else 'N/A'
    )
    exploiter_rate = (
        f'{exploiter_success}/{builder_success} ({exploiter_success / builder_success * 100:.1f}%)'
        if builder_success > 0
        else 'N/A'
    )
    fixer_rate = (
        f'{fixer_success}/{exploiter_success} ({fixer_success / exploiter_success * 100:.1f}%)'
        if exploiter_success > 0
        else 'N/A'
    )

    return {
        'total': total,
        'success': fixer_success,
        'builder_success_rate': builder_rate,
        'exploiter_success_rate': exploiter_rate,
        'fixer_success_rate': fixer_rate,
        'avg_cost': avg_cost,
        'total_cost': total_cost,
        'avg_steps': avg_steps,
    }


def calculate_project_statistics(
    results: List[AnalysisResult],
) -> Dict[str, List[float]]:
    """Calculate statistics per project."""
    # Group results by project
    projects = defaultdict(list)
    for result in results:
        project_name = result.project_name.replace('.cve', '')
        projects[project_name].append(result)

    # Calculate rates for each project
    project_stats = {}
    for project_name, project_results in projects.items():
        total = len(project_results)
        builder_success = sum(
            1 for r in project_results if r.test_result.builder.success
        )
        exploiter_success = sum(
            1 for r in project_results if r.test_result.exploiter.success
        )
        fixer_success = sum(1 for r in project_results if r.test_result.fixer.success)

        builder_rate = builder_success / total * 100 if total > 0 else 0
        exploiter_rate = (
            exploiter_success / builder_success * 100 if builder_success > 0 else 0
        )
        fixer_rate = (
            fixer_success / exploiter_success * 100 if exploiter_success > 0 else 0
        )

        # Calculate average cost and steps
        valid_costs = [r.cost for r in project_results if r.cost is not None]
        avg_cost = sum(valid_costs) / len(valid_costs) if valid_costs else 0
        avg_steps = sum(r.steps for r in project_results) / total if total > 0 else 0

        # Include all projects regardless of fixer success
        project_stats[project_name] = [
            total,
            builder_rate,
            exploiter_rate,
            fixer_rate,
            fixer_success,  # Count of successful fixer instances
            avg_cost,
            avg_steps,
            builder_success,  # Actual count of built instances
            exploiter_success,  # Actual count of exploited instances
        ]

    return project_stats


def create_table(results: List[AnalysisResult]) -> Table:
    table = Table(title='Analysis Results', box=box.ROUNDED)

    # Add columns
    table.add_column('Instance ID', style='cyan')
    table.add_column('Project', style='blue')
    table.add_column('Builder', style='green')
    table.add_column('Exploiter', style='green')
    table.add_column('Fixer', style='green')
    table.add_column('Cost', style='yellow')
    table.add_column('Steps', style='magenta')

    # Sort results by instance_id
    sorted_results = sorted(results, key=lambda x: x.instance_id)

    # Add rows
    for result in sorted_results:
        table.add_row(
            str(result.instance_id),
            str(result.project_name.replace('.cve', '')),
            format_boolean(result.test_result.builder.success),
            format_boolean(result.test_result.exploiter.success),
            format_boolean(result.test_result.fixer.success),
            f'{result.cost:.2f}' if result.cost is not None else 'N/A',
            str(result.steps),
        )

    return table


def create_stats_panel(stats: Dict[str, Any]) -> Table:
    """Create a table with statistics."""
    stats_table = Table(title='Results Summary', box=box.ROUNDED, border_style='blue')

    # Add columns
    stats_table.add_column('Metric', style='cyan')
    stats_table.add_column('Value', style='yellow')

    # Add rows
    stats_table.add_row('Total Instances', str(stats['total']))
    stats_table.add_row('Successful Instances', str(stats['success']))

    # Success rates - already formatted as strings with percentages
    stats_table.add_row('Builder Success Rate', stats['builder_success_rate'])
    stats_table.add_row('Exploiter Success Rate', stats['exploiter_success_rate'])
    stats_table.add_row('Fixer Success Rate', stats['fixer_success_rate'])

    # Cost metrics
    stats_table.add_row('Total Cost', f'${stats["total_cost"]:.2f}')
    stats_table.add_row('Average Cost per Instance', f'${stats["avg_cost"]:.2f}')

    # Steps
    stats_table.add_row('Average Steps per Instance', f'{stats["avg_steps"]:.1f}')

    return stats_table


def print_project_statistics(project_stats: Dict[str, List[float]]):
    """Print project-specific statistics in the required format."""
    # Sort projects with new priority order
    sorted_projects = sorted(
        project_stats.items(),
        # key=lambda x: (-x[1][0], -x[1][4], -x[1][1], -x[1][2], -x[1][3]),
        key=lambda x: (-x[1][4], -x[1][0], -x[1][1], -x[1][2], -x[1][3]),
    )

    print('\n## Success rate of Builder')
    for project, rates in sorted_projects:
        print(f'({rates[1]:.1f}, {project})')

    print('\n## Success rate of Exploiter')
    for project, rates in sorted_projects:
        print(f'({rates[2]:.1f}, {project})')

    print('\n## Success rate of Fixer')
    for project, rates in sorted_projects:
        print(f'({rates[3]:.1f}, {project})')


def print_project_statistics_markdown(
    console: Console, project_stats: Dict[str, List[float]]
):
    """Print project statistics in rich markdown format."""
    # Sort projects by multiple keys in priority order:
    # 1. # Seed (descending)
    # 2. # Verified (descending)
    # 3. Builder success rate (descending)
    # 4. Exploiter success rate (descending)
    # 5. Fixer success rate (descending)
    sorted_projects = sorted(
        project_stats.items(),
        # key=lambda x: (-x[1][0], -x[1][4], -x[1][1], -x[1][2], -x[1][3]),
        key=lambda x: (-x[1][4], -x[1][0], -x[1][1], -x[1][2], -x[1][3]),
    )

    # Create markdown table with new column order
    markdown = '# Project Statistics\n\n'
    markdown += '| Project | # Seed | # Built | # Exploited | # Verified | Builder % | Exploiter % | Fixer % | Avg Cost | Avg Steps |\n'
    markdown += '|---------|--------|---------|------------|------------|----------|-------------|---------|----------|----------|\n'

    # Add rows for each project with new column order
    for project, stats in sorted_projects:
        instances = int(stats[0])
        builder = stats[1]
        exploiter = stats[2]
        fixer = stats[3]
        verified = int(stats[4])
        cost = stats[5]
        steps = stats[6]
        built = int(stats[7])
        exploited = int(stats[8])

        markdown += f'| {project} | {instances} | {built} | {exploited} | {verified} | {builder:.1f} | {exploiter:.1f} | {fixer:.1f} | {cost:.2f} | {steps:.1f} |\n'

    # Print as rich markdown using the Markdown class
    md = Markdown(markdown)
    console.print(md)

    # Also print in the requested format with new column order
    console.print('\n# Plain Format', style='bold')
    for project, stats in sorted_projects:
        instances = int(stats[0])
        builder = stats[1]
        exploiter = stats[2]
        fixer = stats[3]
        verified = int(stats[4])
        cost = stats[5]
        steps = stats[6]
        built = int(stats[7])
        exploited = int(stats[8])

        # console.print(
        #     f'{project} & {instances} & {built} & {exploited} & {verified} & {builder:.1f} & {exploiter:.1f} & {fixer:.1f} & {cost:.2f} & {steps:.1f}'
        # )

        console.print(
            f'{project} & {instances} & {verified} & {builder:.1f} & {exploiter:.1f} & {fixer:.1f} & {cost:.2f} & {steps:.1f}'
        )


def main():
    args = parse_args()
    instances = []

    try:
        with open(args.input_file, 'r') as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    instance = json.loads(line)
                    instances.append(instance)
    except Exception as e:
        print(f'Error loading input file: {e}')
        return

    results = [analyze_instance(instance) for instance in instances]

    # Calculate statistics
    stats = calculate_statistics(results)
    project_stats = calculate_project_statistics(results)

    # Create and display table and stats
    console = Console()
    console.print(create_table(results))
    console.print('')  # Add space between table and stats
    console.print(create_stats_panel(stats))

    # Print project-specific statistics in markdown format
    print_project_statistics_markdown(console, project_stats)


if __name__ == '__main__':
    main()
