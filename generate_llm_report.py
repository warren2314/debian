import os
import sys
from fpdf import FPDF
import openai

class ReportGenerator:
    def __init__(self, sbom_dir, trivy_dir, output_file):
        self.sbom_dir = sbom_dir
        self.trivy_dir = trivy_dir
        self.output_file = output_file
        self.sbom_data = ""
        self.trivy_data = ""
        self.summary = ""

    def parse_results(self):
        # Read SBOM results
        for filename in os.listdir(self.sbom_dir):
            if filename.endswith(".txt") or filename.endswith(".json"):
                with open(os.path.join(self.sbom_dir, filename), 'r') as file:
                    self.sbom_data += file.read() + "\n"

        # Read Trivy results
        for filename in os.listdir(self.trivy_dir):
            if filename.endswith(".txt") or filename.endswith(".json"):
                with open(os.path.join(self.trivy_dir, filename), 'r') as file:
                    self.trivy_data += file.read() + "\n"

    def generate_llm_summary(self):
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            raise ValueError("The OpenAI API key must be set as an environment variable (OPENAI_API_KEY).")

        prompt = (
            "You are a cybersecurity analyst. Analyze the following SBOM and Trivy vulnerability scan results and provide a summary report that a junior application security specialist can understand. "
            "Include key findings, critical vulnerabilities, and general security recommendations.\n\n"
            "SBOM Analysis:\n" + self.sbom_data + "\n\n"
            "Trivy Vulnerability Scan Results:\n" + self.trivy_data
        )

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1000,
            temperature=0.7
        )

        self.summary = response['choices'][0]['message']['content'].strip()

    def generate_pdf_report(self):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.cell(200, 10, txt="LLM-Based Security Report", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt="Summary:", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, txt=self.summary)

        pdf.output(self.output_file)

    def generate_report(self):
        self.parse_results()
        self.generate_llm_summary()
        self.generate_pdf_report()
        print(f"PDF report generated: {self.output_file}")

# Main script
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python generate_llm_report.py <sbom_results_dir> <trivy_results_dir> <output_file>")
        sys.exit(1)

    sbom_results_dir = sys.argv[1]
    trivy_results_dir = sys.argv[2]
    output_file = sys.argv[3]

    try:
        report_generator = ReportGenerator(sbom_results_dir, trivy_results_dir, output_file)
        report_generator.generate_report()
    except ValueError as e:
        print(e)
        sys.exit(1)
