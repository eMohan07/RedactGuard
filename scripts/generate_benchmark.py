import json
from pathlib import Path

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "data" / "benchmark"
BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

DOCS = [
    {
        "id": "doc_01_meeting_notes.txt",
        "text": """EXECUTIVE STRATEGY MEETING NOTES
Date: October 14, 2024
Attendees: Richa Sharma (Head of Product), R. Sharma (Acting Lead), Vikram Malhotra (Engineering)
Project Reference: PX-2024-77
Release Date: 15/11/2024

Discussion Points:
1. The sprint velocity for PX-2024-77 has improved.
2. Richa Sharma will coordinate with customer success regarding pilot feedback.
3. Contact email for escalations: richa.sharma@enterprise.in or call +91 98230 11223.
4. Next sync scheduled for next Tuesday at 10:00 AM.""",
        "pii": [
            {"text": "Richa Sharma", "type": "NAME"},
            {"text": "R. Sharma", "type": "NAME"},
            {"text": "Vikram Malhotra", "type": "NAME"},
            {"text": "Richa Sharma", "type": "NAME"},
            {"text": "richa.sharma@enterprise.in", "type": "EMAIL"},
            {"text": "+91 98230 11223", "type": "PHONE"}
        ]
    },
    {
        "id": "doc_02_medical_intake.txt",
        "text": """PATIENT CLINICAL INTAKE
Date: 12-05-2024
Patient Name: Anand Kulkarni
Date of Birth: 1985-08-22
Aadhaar Number: 3678 4590 1234
Mobile: +91 94220 54321
Address: 12 Shivaji Nagar, Pune, MH 411005
Vitals: BP 120/80 mmHg, Pulse 72 bpm. Ref # MED-8891.""",
        "pii": [
            {"text": "Anand Kulkarni", "type": "NAME"},
            {"text": "3678 4590 1234", "type": "ID"},
            {"text": "+91 94220 54321", "type": "PHONE"},
            {"text": "12 Shivaji Nagar, Pune, MH 411005", "type": "ADDRESS"}
        ]
    },
    {
        "id": "doc_03_vendor_invoice.txt",
        "text": """VENDOR INVOICE
Invoice No: INV-2024-9982
Date: 2024-09-30
Vendor: Acme Solutions Pvt Ltd
Contact: Rajesh Gupta
Email: accounts@acmesolutions.com
Account Number: 981273645102
Product Code: PX-2024-77
Amount Due: INR 45,000""",
        "pii": [
            {"text": "Rajesh Gupta", "type": "NAME"},
            {"text": "accounts@acmesolutions.com", "type": "EMAIL"},
            {"text": "981273645102", "type": "ID"}
        ]
    },
    {
        "id": "doc_04_offer_letter.txt",
        "text": """APPOINTMENT & OFFER LETTER
Candidate: Priya Nair
Employee ID: EMP-9421
Permanent Account Number (PAN): ABCPN1234K
Official Contact: priya.nair@techfirm.co.in
Reporting Manager: Dr. Arvind Patel
Start Date: 01-12-2024""",
        "pii": [
            {"text": "Priya Nair", "type": "NAME"},
            {"text": "EMP-9421", "type": "ID"},
            {"text": "ABCPN1234K", "type": "ID"},
            {"text": "priya.nair@techfirm.co.in", "type": "EMAIL"},
            {"text": "Dr. Arvind Patel", "type": "NAME"}
        ]
    },
    {
        "id": "doc_05_signature_block.txt",
        "text": """Sincerely and Respectfully,

Sunil Deshmukh
Managing Director, Apex Logistics
Direct Tel: 020-25678901
Obfuscated Email: sunil.deshmukh [at] apexlogistics [dot] com
Office: 404 Senapati Bapat Marg, Pune, MH 411016""",
        "pii": [
            {"text": "Sunil Deshmukh", "type": "NAME"},
            {"text": "020-25678901", "type": "PHONE"},
            {"text": "sunil.deshmukh [at] apexlogistics [dot] com", "type": "EMAIL"},
            {"text": "404 Senapati Bapat Marg, Pune, MH 411016", "type": "ADDRESS"}
        ]
    },
    {
        "id": "doc_07_email_thread.txt",
        "text": """From: client.service [at] globalfin dot org
To: amit.joshi@bankcorp.in
Date: November 2, 2024
Subject: Verification of Beneficiary

Dear Amit Joshi,
Please confirm registration details for customer S. K. Rao.
Registered Phone: 9876543210
Case Reference: CAS-443912.
Thank you.""",
        "pii": [
            {"text": "client.service [at] globalfin dot org", "type": "EMAIL"},
            {"text": "amit.joshi@bankcorp.in", "type": "EMAIL"},
            {"text": "Amit Joshi", "type": "NAME"},
            {"text": "S. K. Rao", "type": "NAME"},
            {"text": "9876543210", "type": "PHONE"}
        ]
    },
    {
        "id": "doc_08_hr_incident.txt",
        "text": """INTERNAL HR REPORT - AMBIGUOUS SURNAME TEST
Date: October 18, 2024
Officer: Deepa Menon
Employee A: Richa Sharma (Product Lead)
Employee B: Rajiv Sharma (Sales Executive)
Witness: Sharma reported seeing the incident near Floor 3 elevator.
Contact Phone: +91 91234 56789""",
        "pii": [
            {"text": "Deepa Menon", "type": "NAME"},
            {"text": "Richa Sharma", "type": "NAME"},
            {"text": "Rajiv Sharma", "type": "NAME"},
            {"text": "Sharma", "type": "NAME"},
            {"text": "+91 91234 56789", "type": "PHONE"}
        ]
    },
    {
        "id": "doc_09_bank_statement.txt",
        "text": """HDFC BANK CUSTOMER ADVICE
Account Holder: Meera Sen
Savings Account: 50100234567890
PAN: ABCPS5678M
Branch: MG Road, Bangalore, KA 560001
Date of Transaction: 2024-10-15
Transaction Reference: TXN-998822114""",
        "pii": [
            {"text": "Meera Sen", "type": "NAME"},
            {"text": "50100234567890", "type": "ID"},
            {"text": "ABCPS5678M", "type": "ID"},
            {"text": "MG Road, Bangalore, KA 560001", "type": "ADDRESS"}
        ]
    },
    {
        "id": "doc_10_consulting_agreement.txt",
        "text": """INDEPENDENT CONSULTING AGREEMENT
This agreement is made between Nova Analytics and the CFO of a Pune-based firm,
operating under legal identification number AADHAAR 4589 1234 9012.
Signee: R. Sharma
Email: r.sharma@consultant.in
Notice Address: 88 Bund Garden Road, Pune, MH 411001""",
        "pii": [
            {"text": "4589 1234 9012", "type": "ID"},
            {"text": "R. Sharma", "type": "NAME"},
            {"text": "r.sharma@consultant.in", "type": "EMAIL"},
            {"text": "88 Bund Garden Road, Pune, MH 411001", "type": "ADDRESS"}
        ]
    },
    {
        "id": "doc_11_landline_inquiry.txt",
        "text": """CUSTOMER SUPPORT DESK CALL LOG
Ticket: TCK-89102
Caller: Suresh Iyer
Registered Landline: 022-24123456
Registered Mobile: +91 98200 98200
Query: Issue with home delivery to Flat 101, Palm Court, Mumbai, MH 400050.
Agent ID: AGT-551""",
        "pii": [
            {"text": "Suresh Iyer", "type": "NAME"},
            {"text": "022-24123456", "type": "PHONE"},
            {"text": "+91 98200 98200", "type": "PHONE"},
            {"text": "Flat 101, Palm Court, Mumbai, MH 400050", "type": "ADDRESS"}
        ]
    },
    {
        "id": "doc_12_executive_bio.txt",
        "text": """SPEAKER PROFILE
Name: Tanvi Rao
Designation: Vice President at a Mumbai fintech startup
Contact: tanvi.rao [at] fintechleaders dot org
Mobile: +91 98111 22334
Biography: Tanvi has 15 years experience leading payment gateway security.""",
        "pii": [
            {"text": "Tanvi Rao", "type": "NAME"},
            {"text": "tanvi.rao [at] fintechleaders dot org", "type": "EMAIL"},
            {"text": "+91 98111 22334", "type": "PHONE"}
        ]
    },
    {
        "id": "doc_13_patient_discharge.txt",
        "text": """DISCHARGE ADVICE
Patient: Rohan Roy
Attending Doctor: Dr. Arvind Patel
Emergency Contact: +91 99887 76655
Discharge Date: 18-11-2024
Prescribed: Tab Paracetamol 650mg TDS x 3 days.
Hospital Registration: HOSP-44120""",
        "pii": [
            {"text": "Rohan Roy", "type": "NAME"},
            {"text": "Dr. Arvind Patel", "type": "NAME"},
            {"text": "+91 99887 76655", "type": "PHONE"}
        ]
    },
    {
        "id": "doc_14_lease_agreement.txt",
        "text": """RESIDENTIAL LEASE SUMMARY
Landlord: Mohan Lal
Tenant: Richa Sharma
Leased Premises: 204 Kalyani Nagar, Pune, MH 411014
Security Deposit: INR 75,000
Tenant Phone: +91 98230 11223
Tenant Email: richa.sharma@personalmail.org""",
        "pii": [
            {"text": "Mohan Lal", "type": "NAME"},
            {"text": "Richa Sharma", "type": "NAME"},
            {"text": "204 Kalyani Nagar, Pune, MH 411014", "type": "ADDRESS"},
            {"text": "+91 98230 11223", "type": "PHONE"},
            {"text": "richa.sharma@personalmail.org", "type": "EMAIL"}
        ]
    },
    {
        "id": "doc_15_travel_itinerary.txt",
        "text": """AIRLINE PASSENGER ITINERARY
Passenger: Alok Kumar
Booking Reference: PNR-78AZ9
Frequent Flyer ID: FF-990218
Email: alok.kumar@airtravel.com
Mobile: 9845012345
Flight: AI-804 from DEL to PNQ on 2024-11-25""",
        "pii": [
            {"text": "Alok Kumar", "type": "NAME"},
            {"text": "FF-990218", "type": "ID"},
            {"text": "alok.kumar@airtravel.com", "type": "EMAIL"},
            {"text": "9845012345", "type": "PHONE"}
        ]
    },
    {
        "id": "doc_16_performance_review.txt",
        "text": """ANNUAL APPRAISAL REVIEW
Employee Name: Sneha Bhatt
Employee Code: EMP-7721
PAN Number: BHTPS9921L
Manager: Vikram Malhotra
Department: Cloud Operations
Email: sneha.bhatt@corpcloud.net""",
        "pii": [
            {"text": "Sneha Bhatt", "type": "NAME"},
            {"text": "EMP-7721", "type": "ID"},
            {"text": "BHTPS9921L", "type": "ID"},
            {"text": "Vikram Malhotra", "type": "NAME"},
            {"text": "sneha.bhatt@corpcloud.net", "type": "EMAIL"}
        ]
    },
    {
        "id": "doc_17_support_ticket.txt",
        "text": """IT HELPDESK TICKET
User Name: Kiran Varma
IP Address: 192.168.1.105
Workstation: WS-PUNE-09
User Phone: 020-66778899
Issue Summary: VPN authentication failure after password reset.
Date: 2024-11-19""",
        "pii": [
            {"text": "Kiran Varma", "type": "NAME"},
            {"text": "192.168.1.105", "type": "ID"},
            {"text": "020-66778899", "type": "PHONE"}
        ]
    },
    {
        "id": "doc_18_board_minutes.txt",
        "text": """MINUTES OF BOARD OF DIRECTORS MEETING
Meeting held at: 500 Nariman Point, Mumbai, MH 400021
Chairman: Harsh Vardhan
Chief Financial Officer: R. Sharma
Corporate Secretary: Deepa Menon
Resolution Ref: BR-2024-X4
Contact: secretarial@conglomerate.com""",
        "pii": [
            {"text": "500 Nariman Point, Mumbai, MH 400021", "type": "ADDRESS"},
            {"text": "Harsh Vardhan", "type": "NAME"},
            {"text": "R. Sharma", "type": "NAME"},
            {"text": "Deepa Menon", "type": "NAME"},
            {"text": "secretarial@conglomerate.com", "type": "EMAIL"}
        ]
    }
]

def generate_benchmark():
    ground_truth = {}
    
    for item in DOCS:
        file_path = BENCHMARK_DIR / item["id"]
        text = item["text"].strip()
        file_path.write_text(text, encoding="utf-8")
        
        # Calculate exact offsets
        labeled_spans = []
        for p in item["pii"]:
            val = p["text"]
            cat = p["type"]
            idx = 0
            while True:
                pos = text.find(val, idx)
                if pos == -1:
                    break
                labeled_spans.append({
                    "text": val,
                    "type": cat,
                    "start_char": pos,
                    "end_char": pos + len(val)
                })
                idx = pos + len(val)
                
        # Deduplicate identical spans
        unique_spans = []
        seen = set()
        for s in labeled_spans:
            key = (s["text"], s["start_char"], s["end_char"])
            if key not in seen:
                seen.add(key)
                unique_spans.append(s)
                
        ground_truth[item["id"]] = {
            "text": text,
            "spans": unique_spans
        }

    # Generate Two-Column PDF (doc_06_two_column.pdf)
    try:
        import fitz
        pdf_path = BENCHMARK_DIR / "doc_06_two_column.pdf"
        doc = fitz.open()
        page = doc.new_page(width=595, height=842) # A4
        
        # Left column
        col1_text = (
            "CASE REPORT: CLINICAL AUDIT\n\n"
            "Attending Physician:\nDr. Arvind Patel\n\n"
            "Patient Name:\nRicha Sharma\n\n"
            "Contact Email:\nricha.sharma@healthclinic.org\n\n"
            "Medical Record: MRN-889012"
        )
        page.insert_textbox(fitz.Rect(50, 50, 270, 750), col1_text, fontsize=11)
        
        # Right column
        col2_text = (
            "EMERGENCY CONTACT & BILLING\n\n"
            "Primary Contact:\nRajiv Sharma\n\n"
            "Emergency Phone:\n+91 98230 44556\n\n"
            "Residential Address:\n101 Koregaon Park, Pune, MH 411001\n\n"
            "Account Number: 998811223344"
        )
        page.insert_textbox(fitz.Rect(325, 50, 545, 750), col2_text, fontsize=11)
        
        doc.save(pdf_path)
        doc.close()
        
        # Read extracted text to assign ground truth for PDF
        read_doc = fitz.open(pdf_path)
        pdf_extracted = read_doc[0].get_text("text")
        read_doc.close()
        
        pdf_pii = [
            {"text": "Dr. Arvind Patel", "type": "NAME"},
            {"text": "Richa Sharma", "type": "NAME"},
            {"text": "richa.sharma@healthclinic.org", "type": "EMAIL"},
            {"text": "MRN-889012", "type": "ID"},
            {"text": "Rajiv Sharma", "type": "NAME"},
            {"text": "+91 98230 44556", "type": "PHONE"},
            {"text": "101 Koregaon Park, Pune, MH 411001", "type": "ADDRESS"},
            {"text": "998811223344", "type": "ID"}
        ]
        
        pdf_spans = []
        for p in pdf_pii:
            pos = pdf_extracted.find(p["text"])
            if pos != -1:
                pdf_spans.append({
                    "text": p["text"],
                    "type": p["type"],
                    "start_char": pos,
                    "end_char": pos + len(p["text"])
                })
        ground_truth["doc_06_two_column.pdf"] = {
            "text": pdf_extracted,
            "spans": pdf_spans
        }
        print("Generated two-column PDF benchmark.")
    except Exception as e:
        print(f"PyMuPDF generation note: {e}")

    # Write ground truth JSON benchmark
    gt_file = BENCHMARK_DIR / "ground_truth.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
        
    print(f"Generated {len(ground_truth)} benchmark documents in {BENCHMARK_DIR}")

if __name__ == "__main__":
    generate_benchmark()
