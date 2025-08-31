import fitz
import pandas as pd
import os
import uuid
import re

def normalize_text(text):
    """Remove spaces & lowercase for safe comparison"""
    return re.sub(r'\s+', '', str(text)).strip().lower()

def highlight_pf(pdf_path, excel_path, output_folder="results"):
    """
    PF Highlighter (Optimized)
    - Sirf UAN number highlight karega (row nahi)
    - Agar page me 'EMPLOYEE'S PROVIDENT FUND ORGANISATION' likha ho to usko bhi highlight karega
    - Sirf matched pages ka PDF banega
    - Jo Excel me hai par PDF me nahi mile → alag Excel file
    """
    df = pd.read_excel(excel_path, header=None)
    excel_values_raw = df[0].astype(str).tolist()
    excel_values = [normalize_text(v) for v in excel_values_raw]

    os.makedirs(output_folder, exist_ok=True)

    pdf_doc = fitz.open(pdf_path)
    matched_pages = []
    matched_values = set()

    FIXED_TEXT = "EMPLOYEE'S PROVIDENT FUND ORGANISATION"

    # check each page
    for page_num in range(len(pdf_doc)):
        page = pdf_doc[page_num]
        words = page.get_text("words")  # (x0, y0, x1, y1, word,...)
        page_matched = False

        # normalize words
        normalized_words = [(w, normalize_text(w[4])) for w in words]

        # ---- UAN Numbers ----
        for raw_val, val in zip(excel_values_raw, excel_values):
            if not val:
                continue

            # find UAN matches
            found = [w for w, norm in normalized_words if norm == val]
            if found:
                page_matched = True
                matched_values.add(raw_val)

                # highlight only the exact word (UAN number)
                for w in found:
                    x0, y0, x1, y1, *_ = w
                    rect = fitz.Rect(x0, y0, x1, y1)
                    page.add_highlight_annot(rect)

        # ---- Fixed Line (search directly) ----
        fixed_instances = page.search_for(FIXED_TEXT, quads=False)
        if fixed_instances:
            page_matched = True
            for inst in fixed_instances:
                page.add_highlight_annot(inst)

        if page_matched:
            matched_pages.append(page_num)

    # save only matched pages
    output_pdf_path = None
    if matched_pages:
        new_pdf = fitz.open()
        for num in matched_pages:
            new_pdf.insert_pdf(pdf_doc, from_page=num, to_page=num)
        output_pdf_path = os.path.join(output_folder, f"pf_highlighted_{uuid.uuid4().hex}.pdf")
        new_pdf.save(output_pdf_path)

    # save unmatched UANs
    not_found = [raw for raw in excel_values_raw if raw not in matched_values]
    not_found_path = None
    if not_found:
        not_found_df = pd.DataFrame(not_found)
        not_found_path = os.path.join(output_folder, f"pf_Data_Not_Found_{uuid.uuid4().hex}.xlsx")
        not_found_df.to_excel(not_found_path, index=False, header=False)

    pdf_doc.close()
    return output_pdf_path, not_found_path
