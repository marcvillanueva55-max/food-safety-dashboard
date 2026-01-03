import streamlit as st
import pandas as pd

# ==========================================
# 1. THE RULES DATABASE
# ==========================================

# --- Rules from "BEN-RF-OM 2026 Pre Planting Assessment Buffers.pdf" ---
RULES_BEN_OMF = {
    "Bardin": {"Prohibited": [], "Buffered": [], "Elevated": ["6", "8", "9", "10"]},
    "Corey": {"Prohibited": [], "Buffered": [], "Elevated": ["616", "615", "614", "613"]},
    "East Hansen": {"Prohibited": [], "Buffered": [], "Elevated": ["41", "44"]},
    "Garlinger": {"Prohibited": [], "Buffered": [], "Elevated": ["4", "5", "12", "3", "2", "1", "10", "18", "17"]},
    "Hageman": {"Prohibited": [], "Buffered": [], "Elevated": ["12", "13", "14", "15", "18E", "19", "25"]},
    "Kantro": {"Prohibited": [], "Buffered": [], "Elevated": ["44", "43", "39", "38", "37", "36"]},
    "Lower Patrick": {"Prohibited": [], "Buffered": [], "Elevated": ["22E", "22W"]},
    "Martella Home": {"Prohibited": [], "Buffered": ["6", "7"], "Elevated": ["6", "7"]},
    "Ocean": {"Prohibited": [], "Buffered": [], "Elevated": ["11", "10.9", "12"]},
    "Pedrazzi": {"Prohibited": [], "Buffered": [], "Elevated": ["701", "702", "703", "704", "705", "706", "708", "712", "717", "709"]},
    "Spence": {"Prohibited": [], "Buffered": [], "Elevated": ["2"]},
    "Upper Patrick": {"Prohibited": [], "Buffered": ["13", "16", "19A", "19"], "Elevated": ["13", "16", "19A", "19", "1"]},
    "Vessey": {"Prohibited": [], "Buffered": ["6", "7", "18"], "Elevated": ["6", "7", "18"]},
    "Walters": {"Prohibited": [], "Buffered": [], "Elevated": ["43", "37"]},
    "Watson": {"Prohibited": [], "Buffered": [], "Elevated": ["0", "1", "9", "8", "6"]},
}

# --- Rules from "Ready Pac 2026 Pre Planting Assessment Buffers.pdf" ---
RULES_READY_PAC = {
    "Bardin": {"Prohibited": ["6", "8", "9", "10"], "Buffered": [], "Elevated": []},
    "East Hansen": {"Prohibited": ["41", "44", "42", "45"], "Buffered": [], "Elevated": []},
    "Hageman": {"Prohibited": ["12", "13", "14", "15", "18E", "25"], "Buffered": [], "Elevated": []},
    "Kantro": {"Prohibited": ["32", "34", "35", "36", "37", "38", "39", "40", "43", "44"], "Buffered": ["31"], "Elevated": []},
    "Lower Patrick": {"Prohibited": ["ALL"], "Buffered": [], "Elevated": []},
    "Martella Home": {"Prohibited": ["6", "7"], "Buffered": [], "Elevated": []},
    "Spence": {"Prohibited": [], "Buffered": ["2"], "Elevated": []},
    "Upper Patrick": {"Prohibited": [], "Buffered": ["13", "16", "19A", "19"], "Elevated": []},
    "Vessey": {"Prohibited": [], "Buffered": ["6", "7", "18"], "Elevated": []},
    "Vineyard": {"Prohibited": ["1", "2", "3", "4", "5", "6"], "Buffered": [], "Elevated": []},
    "Walters": {"Prohibited": ["37"], "Buffered": ["42", "43"], "Elevated": []},
    "Watson": {"Prohibited": ["2", "7", "10"], "Buffered": ["0", "1", "5", "6", "9", "8"], "Elevated": []},
    "West Hansen": {"Prohibited": [], "Buffered": ["All"], "Elevated": []}
}

# --- Rules from "Church Brothers 2026 Pre-Planting Buffers.pdf" ---
# Special Key: "Prohibited_LG" applies only to Leafy Greens
RULES_CHURCH = {
    "Bardin": {"Prohibited": [], "Buffered": ["6", "8", "9", "10", "11"], "Elevated": ["6", "8", "9", "10", "11"]},
    "Corey": {"Prohibited": [], "Buffered": [], "Elevated": ["616", "615", "614", "613"]},
    "Davis": {"Prohibited_LG": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "15", "18"], "Buffered": [], "Elevated": []},
    "East Hansen": {"Prohibited": ["41", "44"], "Buffered": ["41", "44"], "Elevated": ["41", "44"]},
    "Garlinger": {"Prohibited": [], "Buffered": ["4", "3", "2"], "Elevated": []},
    "Hageman": {"Prohibited": ["12", "13", "14", "15", "19", "18E", "25"], "Buffered": [], "Elevated": ["12", "13", "14", "15", "18", "19", "25"]},
    "Kantro": {"Prohibited_LG": ["37", "36", "38", "39", "32", "44", "43"], "Buffered": ["34", "35", "42", "33"], "Elevated": []},
    "Lanini": {"Prohibited_LG": ["ALL"], "Buffered": [], "Elevated": []},
    "Lower Patrick": {"Prohibited": ["22E", "22W"], "Buffered": [], "Elevated": ["22E", "22W"]},
    "Martella Home": {"Prohibited_LG": ["ALL"], "Buffered": [], "Elevated": []},
    "Ocean": {"Prohibited": [], "Buffered": [], "Elevated": ["11", "10", "9", "12"]},
    "Pedrazzi": {"Prohibited": [], "Buffered": ["701", "702", "703", "704", "705", "706"], "Elevated": ["701", "702", "703", "704", "705", "706", "708", "712", "717", "709"]},
    "Spence": {"Prohibited": [], "Buffered": ["2"], "Elevated": ["1", "2"]},
    "Upper Patrick": {"Prohibited": ["13", "16", "19A"], "Buffered": [], "Elevated": ["13", "16", "19A", "19"]},
    "Vessey": {"Prohibited": [], "Buffered": ["6", "7", "18"], "Elevated": ["6", "7", "18"]},
    "Walters": {"Prohibited": ["37"], "Buffered": ["42", "43"], "Elevated": ["42", "43"]},
    "Watson": {"Prohibited": [], "Buffered": [], "Elevated": ["0", "1", "9", "8", "6"]},
    "West Hansen": {"Prohibited": [], "Buffered": [], "Elevated": ["24"]}
}

# --- Rules from "Taylor Farms 2026 Pre-Planting Buffers.pdf" ---
RULES_TAYLOR = {
    "Abeloe": {"Prohibited": [], "Buffered": ["2"], "Elevated": []},
    "Alsop": {"Prohibited": [], "Buffered": ["3"], "Elevated": []},
    "Bardin": {"Prohibited": ["6", "8", "9", "10"], "Buffered": [], "Elevated": []},
    "Davis": {"Prohibited": [], "Buffered": ["20", "13", "8", "10"], "Elevated": []},
    "East Hansen": {"Prohibited": [], "Buffered": ["41", "44"], "Elevated": []},
    "Garlinger": {"Prohibited": [], "Buffered": ["25"], "Elevated": []},
    "Hageman": {"Prohibited": ["12", "13", "14", "15", "18E", "19", "20", "21", "25"], "Buffered": ["20", "21", "4"], "Elevated": []},
    "Hansen": {"Prohibited": [], "Buffered": ["32", "33", "35"], "Elevated": []},
    "Lanini": {"Prohibited": [], "Buffered": ["1", "2", "3", "4"], "Elevated": []},
    "Lower Patrick": {"Prohibited": [], "Buffered": ["22E", "22W"], "Elevated": []},
    "Martella": {"Prohibited": [], "Buffered": ["7"], "Elevated": []},
    "Martella Home": {"Prohibited": ["2", "3", "4", "5", "6", "7"], "Buffered": [], "Elevated": []},
    "Pedrazzi": {"Prohibited": [], "Buffered": ["707"], "Elevated": []},
    "Silva": {"Prohibited": [], "Buffered": ["1", "2"], "Elevated": []},
    "Upper Patrick": {"Prohibited": [], "Buffered": ["13", "16", "19A", "19", "1"], "Elevated": []},
    "Vessey": {"Prohibited": [], "Buffered": ["6", "7", "18"], "Elevated": []},
    "Vierra-Cranford": {"Prohibited": [], "Buffered": ["10"], "Elevated": []},
    "Walters": {"Prohibited": ["37"], "Buffered": ["43", "42"], "Elevated": []},
    "Watson": {"Prohibited": [], "Buffered": ["5", "6", "8", "9"], "Elevated": []},
    "West Hansen": {"Prohibited": [], "Buffered": ["24"], "Elevated": []}
}

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

LEAFY_GREENS = ["ML", "RH", "RL", "HL"]

def check_lot_compliance(ranch, lot, rules_set, crop=None):
    """
    Checks a specific ranch/lot against a specific rules dictionary.
    Includes logic for crop-specific prohibitions (Church Brothers).
    """
    issues = []
    lot = str(lot).strip()
    ranch = str(ranch).strip()
    
    if ranch not in rules_set:
        return issues 

    ranch_rules = rules_set[ranch]

    # 1. Standard Prohibited
    if "Prohibited" in ranch_rules:
        if "ALL" in ranch_rules["Prohibited"] or lot in ranch_rules["Prohibited"]:
            issues.append("RED LIGHT: Prohibited Lot")

    # 2. Leafy Green Specific Prohibited (Church Logic)
    if "Prohibited_LG" in ranch_rules and crop in LEAFY_GREENS:
        if "ALL" in ranch_rules["Prohibited_LG"] or lot in ranch_rules["Prohibited_LG"]:
            issues.append(f"RED LIGHT: Prohibited for Leafy Greens ({crop})")

    # 3. Standard Buffered
    if "Buffered" in ranch_rules:
        if "ALL" in ranch_rules["Buffered"] or lot in ranch_rules["Buffered"]:
            issues.append("YELLOW LIGHT: Buffer Required")

    # 4. Elevated Testing
    if "Elevated" in ranch_rules:
        if lot in ranch_rules["Elevated"]:
            issues.append("YELLOW LIGHT: Elevated LGMA Testing Required")
        
    return issues

def analyze_schedule(df):
    results = []
    
    for index, row in df.iterrows():
        ranch = str(row['Ranch']).strip()
        lot = str(row['Lot']).strip()
        comp = str(row['Comp']).strip() # Customer
        crop = str(row['Crop']).strip() 
        
        row_status = "Green"
        comments = []
        
        # --- RULE ENGINE ---
        
        # 1. Bengard / Ocean Mist / River Fresh
        if comp in ["BEN", "OMF", "RF"]:
            found = check_lot_compliance(ranch, lot, RULES_BEN_OMF, crop)
            if found: comments.extend([f"[{comp} Rule]: {i}" for i in found])

        # 2. Ready Pac (BFA) - Also triggers for BEN + ML
        check_bfa = False
        if comp == "BFA":
            check_bfa = True
        elif comp == "BEN" and crop == "ML":
            check_bfa = True
            comments.append("INFO: Checking Ready Pac (BEN + ML trigger)")

        if check_bfa:
            found = check_lot_compliance(ranch, lot, RULES_READY_PAC, crop)
            if found: comments.extend([f"[BFA Rule]: {i}" for i in found])

        # 3. Church Brothers
        if comp == "Church":
            found = check_lot_compliance(ranch, lot, RULES_CHURCH, crop)
            if found: comments.extend([f"[Church Rule]: {i}" for i in found])

        # 4. Taylor Farms
        if comp == "Taylor":
            found = check_lot_compliance(ranch, lot, RULES_TAYLOR, crop)
            if found: comments.extend([f"[Taylor Rule]: {i}" for i in found])

        # --- FINAL STATUS ---
        if any("RED LIGHT" in c for c in comments):
            row_status = "Red"
        elif any("YELLOW LIGHT" in c for c in comments):
            row_status = "Yellow"
            
        results.append({
            "Ranch": ranch,
            "Lot": lot,
            "Comp": comp,
            "Crop": crop,
            "Status": row_status,
            "Compliance Notes": "; ".join(comments) if comments else "Clear to Plant"
        })
        
    return pd.DataFrame(results)

def style_dataframe(df):
    def color_rows(row):
        if row['Status'] == 'Red':
            return ['background-color: #ffcccc'] * len(row)
        elif row['Status'] == 'Yellow':
            return ['background-color: #ffffcc'] * len(row)
        elif row['Status'] == 'Green':
            return ['background-color: #ccffcc'] * len(row)
        return ['background-color: white'] * len(row)

    return df.style.apply(color_rows, axis=1)

# ==========================================
# 3. STREAMLIT APP
# ==========================================

def main():
    st.set_page_config(page_title="2026 Pre-Planting Compliance", layout="wide")
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        st.title("🔐 Food Safety Compliance Portal")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if username == "admin" and password == "foodsafety2026": # Temp Creds
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("Invalid credentials")
        return

    st.sidebar.title("Navigation")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

    st.title("🌱 Pre-Planting Assessment Dashboard 2026")
    st.markdown("""
    **Supported Customers:** Taylor Farms, Ocean Mist (OMF), Church Brothers, Bengard (BEN), Ready Pac (BFA).
    **Logic:**
    * **Red Light:** Prohibited Lots.
    * **Yellow Light:** Buffer Required or Elevated LGMA Testing.
    * **Green Light:** Clear to Plant.
    * **Crop Logic:** Leafy Greens (ML, RH, RL, HL) have stricter rules for Church Brothers.
    """)

    uploaded_file = st.file_uploader("Upload Planting Schedule (Excel)", type=["xlsx", "xls"])

    if uploaded_file:
        try:
            df = pd.read_excel(uploaded_file)
            req_cols = ['Ranch', 'Lot', 'Comp', 'Crop']
            
            if not all(c in df.columns for c in req_cols):
                st.error(f"Excel must contain columns: {req_cols}")
            else:
                st.success("File uploaded. Select customers to scan:")
                
                # Dynamic Filtering
                all_comps = df['Comp'].unique().tolist()
                selected_comps = st.multiselect("Select Customers", all_comps, default=all_comps)
                
                if st.button("Run Compliance Scan"):
                    scan_df = df[df['Comp'].isin(selected_comps)]
                    report = analyze_schedule(scan_df)
                    
                    # Dashboard Metrics
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Total Lots Scanned", len(report))
                    c2.metric("Issues Found (Red)", len(report[report['Status'] == 'Red']))
                    c3.metric("Warnings (Yellow)", len(report[report['Status'] == 'Yellow']))

                    st.write("### Assessment Results")
                    st.dataframe(style_dataframe(report), use_container_width=True)
                    
                    st.download_button(
                        "Download Report",
                        report.to_csv(index=False).encode('utf-8'),
                        "compliance_report_2026.csv",
                        "text/csv"
                    )

        except Exception as e:
            st.error(f"Error processing file: {e}")

if __name__ == "__main__":
    main()
