import fitz  # PyMuPDF
import pandas as pd
import os
import uuid

def highlight_esic(pdf_path, excel_path, output_folder="results"):
    """
    ESIC PDF Highlighter:
    - Highlights full row for Excel values
    - Highlights full line of fixed text "EMPLOYEES' STATE INSURANCE CORPORATION" on every page
    - Saves unmatched Excel values in separate file
    """

    df = pd.read_excel(excel_path, header=None)
    excel_values = df[0].astype(str).tolist()

    os.makedirs(output_folder, exist_ok=True)

    pdf_doc = fitz.open(pdf_path)
    matched_pages = []
    matched_values = set()

    FIXED_TEXT = "EMPLOYEES' STATE INSURANCE CORPORATION"

    for page_num in range(len(pdf_doc)):
        page = pdf_doc[page_num]
        page_matched = False
        words = page.get_text("words")

        # ---- Excel IDs ----
        for val in excel_values:
            val_lower = val.strip().lower()
            if not val_lower:
                continue

            matched_words = [w for w in words if val_lower == w[4].strip().lower()]

            if matched_words:
                page_matched = True
                matched_values.add(val)

                for w in matched_words:
                    x0, y0, x1, y1, *_ = w
                    # full row highlight
                    row_words = [rw for rw in words if abs(rw[1]-y0) < 2 or abs(rw[3]-y1) < 2]
                    if row_words:
                        rect = fitz.Rect(
                            min(rw[0] for rw in row_words),
                            min(rw[1] for rw in row_words),
                            max(rw[2] for rw in row_words),
                            max(rw[3] for rw in row_words)
                        )
                        page.add_highlight_annot(rect)

        # ---- Fixed ESIC Line ----
        # pura text search karo, na ki sirf ek word
        text_instances = page.search_for(FIXED_TEXT, quads=False)
        for inst in text_instances:
            page_matched = True
            page.add_highlight_annot(inst)

        if page_matched:
            matched_pages.append(page_num)

    # Save matched PDF
    output_pdf_path = None
    if matched_pages:
        new_pdf = fitz.open()
        for num in matched_pages:
            new_pdf.insert_pdf(pdf_doc, from_page=num, to_page=num)
        output_pdf_path = os.path.join(output_folder, f"esic_highlighted_{uuid.uuid4().hex}.pdf")
        new_pdf.save(output_pdf_path)

    # Save unmatched Excel IDs
    not_found = [val for val in excel_values if val not in matched_values]
    not_found_path = None
    if not_found:
        not_found_df = pd.DataFrame(not_found)
        not_found_path = os.path.join(output_folder, f"esic_Data_Not_Found_{uuid.uuid4().hex}.xlsx")
        not_found_df.to_excel(not_found_path, index=False, header=False)

    pdf_doc.close()
    return output_pdf_path, not_found_path
