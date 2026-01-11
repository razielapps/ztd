# utils/exporters.py
"""
Report exporters for ZeroTrustDjango Scanner
"""

import json
import csv
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class ReportExporter:
    """Base class for report exporters"""
    
    def __init__(self, report_data: Dict[str, Any]):
        self.report_data = report_data
        
    def export(self, output_path: Path):
        """Export report to specified path"""
        raise NotImplementedError
        
class JSONExporter(ReportExporter):
    """Export report as JSON"""
    
    def export(self, output_path: Path):
        """Export to JSON file"""
        with open(output_path, 'w') as f:
            json.dump(self.report_data, f, indent=2, default=str)
            
class CSVExporter(ReportExporter):
    """Export report as CSV"""
    
    def export(self, output_path: Path):
        """Export to CSV file"""
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write summary
            writer.writerow(["ZeroTrustDjango Security Scan Report"])
            writer.writerow([f"Scan Date: {self.report_data['scan_date']}"])
            writer.writerow([f"Project: {self.report_data['project_path']}"])
            writer.writerow([])
            
            # Write issues
            writer.writerow(["ISSUES"])
            writer.writerow(["Severity", "Category", "Title", "Location", "Recommendation", "CWE ID"])
            
            for result in self.report_data["results"]:
                for issue in result["issues"]:
                    writer.writerow([
                        issue["severity"],
                        issue["category"],
                        issue["title"],
                        issue["location"],
                        issue["recommendation"],
                        issue.get("cwe_id", "N/A")
                    ])
                    
class HTMLExporter(ReportExporter):
    """Export report as HTML"""
    
    def export(self, output_path: Path):
        """Export to HTML file"""
        html = self._generate_html()
        with open(output_path, 'w') as f:
            f.write(html)
            
    def _generate_html(self) -> str:
        """Generate HTML report"""
        summary = self.report_data["summary"]
        
        # Generate severity badges
        severity_badges = ""
        for severity, count in summary["issues_by_severity"].items():
            color_class = f"severity-{severity.lower()}"
            severity_badges += f"""
            <div class="severity-badge {color_class}">
                <span class="severity-label">{severity}</span>
                <span class="severity-count">{count}</span>
            </div>
            """
            
        # Generate issues table
        issues_rows = ""
        for result in self.report_data["results"]:
            for issue in result["issues"]:
                issues_rows += f"""
                <tr class="issue-row severity-{issue['severity'].lower()}">
                    <td>{issue['severity']}</td>
                    <td>{issue['category']}</td>
                    <td>{issue['title']}</td>
                    <td>{issue['location']}</td>
                    <td>{issue['recommendation']}</td>
                </tr>
                """
                
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ZeroTrustDjango Security Scan Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                }}
                .summary {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                }}
                .severity-badges {{
                    display: flex;
                    gap: 15px;
                    margin: 20px 0;
                    flex-wrap: wrap;
                }}
                .severity-badge {{
                    padding: 10px 20px;
                    border-radius: 20px;
                    color: white;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                .severity-critical {{ background: #dc3545; }}
                .severity-high {{ background: #fd7e14; }}
                .severity-medium {{ background: #ffc107; color: #212529; }}
                .severity-low {{ background: #17a2b8; }}
                .severity-info {{ background: #6c757d; }}
                .issues-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 30px 0;
                }}
                .issues-table th {{
                    background: #343a40;
                    color: white;
                    padding: 12px;
                    text-align: left;
                }}
                .issues-table td {{
                    padding: 12px;
                    border-bottom: 1px solid #dee2e6;
                }}
                .issue-row:hover {{
                    background: #f8f9fa;
                }}
                .risk-score {{
                    font-size: 3em;
                    font-weight: bold;
                    text-align: center;
                    margin: 20px 0;
                }}
                .risk-high {{ color: #dc3545; }}
                .risk-medium {{ color: #fd7e14; }}
                .risk-low {{ color: #28a745; }}
                .recommendations {{
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 20px;
                    margin: 30px 0;
                }}
                @media print {{
                    body {{ padding: 0; }}
                    .severity-badges {{ flex-direction: column; }}
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>ZeroTrustDjango Security Scan Report</h1>
                <p>Scan Date: {self.report_data['scan_date']}</p>
                <p>Project: {self.report_data['project_path']}</p>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p>Total Tests: {summary['total_tests']} | 
                   Passed: {summary['passed_tests']} | 
                   Failed: {summary['failed_tests']} | 
                   Total Issues: {summary['total_issues']}</p>
                
                <div class="risk-score {self._get_risk_class(summary['risk_score'])}">
                    {summary['risk_score']:.1f}/100
                </div>
                
                <div class="severity-badges">
                    {severity_badges}
                </div>
            </div>
            
            <h2>Security Issues</h2>
            <table class="issues-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Issue</th>
                        <th>Location</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {issues_rows}
                </tbody>
            </table>
            
            <div class="recommendations">
                <h3>Key Recommendations</h3>
                {self._generate_recommendations()}
            </div>
            
            <script>
                // Add interactive features
                document.addEventListener('DOMContentLoaded', function() {{
                    // Filter by severity
                    const filterButtons = document.querySelectorAll('.filter-btn');
                    filterButtons.forEach(button => {{
                        button.addEventListener('click', function() {{
                            const severity = this.dataset.severity;
                            const rows = document.querySelectorAll('.issue-row');
                            rows.forEach(row => {{
                                if (severity === 'all' || row.classList.contains(`severity-${{severity}}`)) {{
                                    row.style.display = '';
                                }} else {{
                                    row.style.display = 'none';
                                }}
                            }});
                        }});
                    }});
                }});
            </script>
        </body>
        </html>
        """
        return html
        
    def _get_risk_class(self, score: float) -> str:
        """Get CSS class for risk score"""
        if score >= 70:
            return "risk-high"
        elif score >= 40:
            return "risk-medium"
        else:
            return "risk-low"
            
    def _generate_recommendations(self) -> str:
        """Generate HTML for recommendations"""
        critical_issues = []
        for result in self.report_data["results"]:
            for issue in result["issues"]:
                if issue["severity"] in ["CRITICAL", "HIGH"]:
                    critical_issues.append(issue)
                    
        if not critical_issues:
            return "<p>No critical issues found. Good security posture!</p>"
            
        recommendations = "<ul>"
        for i, issue in enumerate(critical_issues[:5], 1):
            recommendations += f'<li><strong>{issue["title"]}</strong>: {issue["recommendation"]}</li>'
        recommendations += "</ul>"
        
        return recommendations
