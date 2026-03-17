from fpdf import FPDF
from datetime import datetime
import os

class ReportGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
    def generate_report(self, stats, attributions, summaries):
        """Generates a professional forensic PDF report."""
        self.pdf.add_page()
        
        # Header
        self.pdf.set_font("Arial", 'B', 24)
        self.pdf.set_text_color(66, 133, 244) # MetaTrace Blue
        self.pdf.cell(0, 20, "METATRACE FORENSIC REPORT", ln=True, align='C')
        
        self.pdf.set_font("Arial", 'I', 10)
        self.pdf.set_text_color(100, 100, 100)
        self.pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        self.pdf.ln(10)
        
        # Executive Summary
        self.pdf.set_font("Arial", 'B', 16)
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.cell(0, 10, "1. Executive Summary", ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font("Arial", '', 11)
        self.pdf.multi_cell(0, 7, (
            "This document contains a non-intrusive forensic analysis of network-level metadata captured "
            "from the suspect device. The analysis focuses on endpoint attribution, behavioral trends, "
            "and potential de-anonymization of encrypted communication channels."
        ))
        self.pdf.ln(5)
        
        # Key Statistics
        self.pdf.set_font("Arial", 'B', 12)
        self.pdf.cell(0, 10, "Key Capture Statistics:", ln=True)
        self.pdf.set_font("Arial", '', 11)
        self.pdf.cell(0, 7, f"- Total Packets Analysed: {stats.get('total_packets', 0)}", ln=True)
        self.pdf.cell(0, 7, f"- Unique Endpoints Identified: {stats.get('unique_endpoints', 0)}", ln=True)
        self.pdf.cell(0, 7, f"- Burst Activity Detected: {stats.get('total_bursts', 0)} events", ln=True)
        self.pdf.ln(10)
        
        # Endpoint Analysis
        self.pdf.set_font("Arial", 'B', 16)
        self.pdf.cell(0, 10, "2. Target Attributions", ln=True)
        self.pdf.ln(5)
        
        for ip, attr in attributions.items():
            self.pdf.set_font("Arial", 'B', 12)
            self.pdf.set_fill_color(240, 240, 240)
            self.pdf.cell(0, 10, f" Endpoint: {ip}", ln=True, fill=True)
            
            self.pdf.set_font("Arial", '', 10)
            self.pdf.cell(50, 7, " Classification:", border=0)
            self.pdf.set_font("Arial", 'B', 10)
            self.pdf.cell(0, 7, f" {attr.get('predicted_network', 'Unknown')}", ln=True)
            
            self.pdf.set_font("Arial", '', 10)
            self.pdf.cell(50, 7, " Confidence Score:", border=0)
            self.pdf.cell(0, 7, f" {attr.get('confidence', 0)*100:.1f}%", ln=True)
            
            geo = attr.get('geo', {})
            if geo:
                self.pdf.cell(50, 7, " Physical Location:", border=0)
                self.pdf.cell(0, 7, f" {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}", ln=True)
                self.pdf.cell(50, 7, " ISP / Provider:", border=0)
                self.pdf.cell(0, 7, f" {geo.get('isp', 'Unknown')}", ln=True)
            
            self.pdf.ln(3)
            # Investigative Summary
            summary = summaries.get(ip, "No specific intelligence gathered.")
            # Clean summary of markdown bolding
            clean_summary = summary.replace("**", "")
            self.pdf.set_font("Arial", 'I', 10)
            self.pdf.multi_cell(0, 6, clean_summary)
            self.pdf.ln(5)
            
        # Footer
        self.pdf.add_page()
        self.pdf.set_font("Arial", 'B', 16)
        self.pdf.cell(0, 10, "3. Conclusion", ln=True)
        self.pdf.ln(5)
        self.pdf.set_font("Arial", '', 11)
        self.pdf.multi_cell(0, 7, (
            "The findings presented in this report are based on static analysis of communication patterns. "
            "High-confidence attributions ( > 80%) strongly suggest the use of the identified network types "
            "for anonymized or encrypted communication. Investigators are advised to correlate these findings "
            "with device-level forensics."
        ))
        
        self.pdf.output(self.output_path)
        return self.output_path
