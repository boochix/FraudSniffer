from __future__ import annotations

import re
import json
import urllib.request
import urllib.error
import difflib
import logging

logger = logging.getLogger(__name__)

# Mock PAN Database
MOCK_PAN_DB = {
    "AGTPV8291K": "Rahul Kumar Verma",
    "ABCDE1234F": "Jane Doe",
    "PANNO1234A": "John Smith",
    "CANAR1234B": "Canara Verified User"
}

# Mock MCA Company Database
MOCK_COMPANIES = {
    "canara": {"cin": "U65110KA1906GOI003313", "status": "ACTIVE", "name": "CANARA BANK"},
    "tcs": {"cin": "L74140MH1995PLC090096", "status": "ACTIVE", "name": "TATA CONSULTANCY SERVICES LIMITED"},
    "infosys": {"cin": "L85110KA1981PLC013115", "status": "ACTIVE", "name": "INFOSYS LIMITED"},
    "reliance": {"cin": "L17110MH1973PLC019786", "status": "ACTIVE", "name": "RELIANCE INDUSTRIES LIMITED"},
    "hdfc": {"cin": "L65920MH1994PLC080618", "status": "ACTIVE", "name": "HDFC BANK LIMITED"},
    "google": {"cin": "U72900DL2003PTC119123", "status": "ACTIVE", "name": "GOOGLE INDIA PRIVATE LIMITED"},
    "microsoft": {"cin": "U72200DL1998PTC095987", "status": "ACTIVE", "name": "MICROSOFT CORPORATION INDIA PRIVATE LIMITED"},
}

# Mock IFSC Database for offline usage
MOCK_IFSC_DB = {
    "CNRB0000101": {
        "BANK": "CANARA BANK",
        "BRANCH": "BANGALORE MAIN",
        "CITY": "BANGALORE",
        "STATE": "KARNATAKA",
        "ADDRESS": "112, J C ROAD, BANGALORE 560002"
    },
    "SBIN0000001": {
        "BANK": "STATE BANK OF INDIA",
        "BRANCH": "MUMBAI MAIN",
        "CITY": "MUMBAI",
        "STATE": "MAHARASHTRA",
        "ADDRESS": "MUMBAI MAIN BRANCH, FORT, MUMBAI 400001"
    },
    "HDFC0000001": {
        "BANK": "HDFC BANK",
        "BRANCH": "MUMBAI - KANJURMARG",
        "CITY": "MUMBAI",
        "STATE": "MAHARASHTRA",
        "ADDRESS": "HDFC BANK LTD., KANJURMARG, MUMBAI 400078"
    },
    "ICIC0000001": {
        "BANK": "ICICI BANK LIMITED",
        "BRANCH": "MUMBAI - BACKBAY RECLAMATION",
        "CITY": "MUMBAI",
        "STATE": "MAHARASHTRA",
        "ADDRESS": "ICICI BANK LTD., RECLAMATION, MUMBAI 400020"
    }
}

def verify_ifsc_code(ifsc: str) -> dict:
    """
    Verify IFSC code. First checks local mock database, then queries Razorpay's 
    free public endpoint. If offline/network fails, falls back to validation based 
    on regex format check to enable fully offline run.
    """
    ifsc = ifsc.strip().upper() if ifsc else ""
    if not ifsc or len(ifsc) != 11:
        return {"valid": False, "error": "Invalid IFSC code format"}
    
    # 1. Local mock registry lookup first
    if ifsc in MOCK_IFSC_DB:
        mock_data = MOCK_IFSC_DB[ifsc]
        return {
            "valid": True,
            "bank": mock_data["BANK"],
            "branch": mock_data["BRANCH"],
            "city": mock_data["CITY"],
            "state": mock_data["STATE"],
            "address": mock_data["ADDRESS"]
        }
        
    # 2. Try network query if online
    url = f"https://ifsc.razorpay.com/{ifsc}"
    try:
        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "FraudSniffer/1.0 (Document Verification Platform)"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                return {
                    "valid": True,
                    "bank": data.get("BANK", ""),
                    "branch": data.get("BRANCH", ""),
                    "city": data.get("CITY", ""),
                    "state": data.get("STATE", ""),
                    "address": data.get("ADDRESS", "")
                }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"valid": False, "error": "IFSC code does not exist"}
        return {"valid": False, "error": f"IFSC lookup HTTP error: {e.code}"}
    except Exception as e:
        logger.warning(f"IFSC lookup failed due to network/timeout error (falling back to offline check): {e}")
        
        # 3. Offline fallback: validate using standard IFSC regex structure
        if re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", ifsc):
            prefix = ifsc[:4]
            bank_name = "MOCK BANK"
            if prefix == "CNRB":
                bank_name = "CANARA BANK"
            elif prefix == "SBIN":
                bank_name = "STATE BANK OF INDIA"
            elif prefix == "HDFC":
                bank_name = "HDFC BANK"
            elif prefix == "ICIC":
                bank_name = "ICICI BANK LIMITED"
                
            return {
                "valid": True,
                "bank": bank_name,
                "branch": "OFFLINE MOCK BRANCH",
                "city": "MUMBAI",
                "state": "MAHARASHTRA",
                "address": "OFFLINE MOCK ADDRESS"
            }
        return {"valid": False, "error": f"IFSC lookup failed: {str(e)}"}
    
    return {"valid": False, "error": "IFSC code does not exist"}

def verify_pan_registry(pan: str, employee_name: str) -> dict:
    """
    Validate PAN structure and match against mock profiles using fuzzy matching.
    """
    pan = pan.strip().upper() if pan else ""
    employee_name = employee_name.strip() if employee_name else ""
    
    if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", pan):
        return {"valid": False, "error": "Invalid PAN format"}
    
    registered_name = MOCK_PAN_DB.get(pan)
    if not registered_name:
        return {
            "valid": False,
            "registered_name": None,
            "match_score": 0.0,
            "error": f"PAN '{pan}' is unregistered"
        }

    # Token-based overlap boost to support middle names (e.g. Rahul Verma vs Rahul Kumar Verma)
    words1 = set(re.findall(r"\w+", employee_name.lower()))
    words2 = set(re.findall(r"\w+", registered_name.lower()))
    
    overlap = 0.0
    if words1 and words2:
        intersection = words1.intersection(words2)
        overlap = len(intersection) / min(len(words1), len(words2))

    base_score = difflib.SequenceMatcher(None, employee_name.lower(), registered_name.lower()).ratio()
    
    # Boost if all words of one name are in the other name
    if overlap >= 1.0:
        score = max(base_score, 0.85)
    else:
        score = base_score
    
    if score >= 0.80:
        return {
            "valid": True,
            "registered_name": registered_name,
            "match_score": round(score, 3)
        }
    else:
        return {
            "valid": False,
            "registered_name": registered_name,
            "match_score": round(score, 3),
            "error": f"Name mismatch: Registered PAN name '{registered_name}' does not match employee '{employee_name}'"
        }

def clean_company_name(name: str) -> str:
    if not name:
        return ""
    name = name.lower()
    name = re.sub(r"[^\w\s]", " ", name)
    suffixes = ["limited", "pvt", "ltd", "private", "co", "corporation", "corp", "bank"]
    words = name.split()
    filtered_words = [w for w in words if w not in suffixes]
    return " ".join(filtered_words).strip()

def verify_company_existence(company_name: str) -> dict:
    """
    Query a mock database of registered Indian private limited entities.
    """
    company_name = company_name.strip() if company_name else ""
    cleaned_input = clean_company_name(company_name)
    if not cleaned_input:
        return {"valid": False, "error": "Company name is empty"}
    
    for key, info in MOCK_COMPANIES.items():
        cleaned_key = clean_company_name(key)
        if cleaned_key in cleaned_input or cleaned_input in cleaned_key:
            return {
                "valid": True,
                "company_name": info["name"],
                "cin": info["cin"],
                "status": info["status"]
            }
            
    return {"valid": False, "error": f"Company '{company_name}' not found in MCA registry"}

def verify_bank_account_penny_drop(account_number: str, ifsc: str, employee_name: str) -> dict:
    """
    Simulate a ₹1 penny-drop query. Returns registered beneficiary name matching the applicant.
    """
    account_number = account_number.strip() if account_number else ""
    employee_name = employee_name.strip() if employee_name else ""
    
    if not account_number or not account_number.isdigit() or not (9 <= len(account_number) <= 18):
        return {"valid": False, "error": "Invalid bank account format"}
    
    # If account ends in 999, simulate mismatch
    if account_number.endswith("999"):
        beneficiary_name = "Unknown Beneficiary"
    else:
        beneficiary_name = employee_name
        
    score = difflib.SequenceMatcher(None, employee_name.lower(), beneficiary_name.lower()).ratio()
    
    if score >= 0.80:
        return {
            "valid": True,
            "beneficiary_name": beneficiary_name,
            "match_score": round(score, 3),
            "message": "Penny drop successful: Account active and beneficiary name matches"
        }
    else:
        return {
            "valid": False,
            "beneficiary_name": beneficiary_name,
            "match_score": round(score, 3),
            "error": f"Beneficiary name mismatch: '{beneficiary_name}' on account does not match '{employee_name}'"
        }


# GST State Codes mapping
GST_STATE_CODES = {
    "01": "Jammu & Kashmir",
    "02": "Himachal Pradesh",
    "03": "Punjab",
    "04": "Chandigarh",
    "05": "Uttarakhand",
    "06": "Haryana",
    "07": "Delhi",
    "08": "Rajasthan",
    "09": "Uttar Pradesh",
    "10": "Bihar",
    "11": "Sikkim",
    "12": "Arunachal Pradesh",
    "13": "Nagaland",
    "14": "Manipur",
    "15": "Mizoram",
    "16": "Tripura",
    "17": "Meghalaya",
    "18": "Assam",
    "19": "West Bengal",
    "20": "Jharkhand",
    "21": "Odisha",
    "22": "Chhattisgarh",
    "23": "Madhya Pradesh",
    "24": "Gujarat",
    "26": "Dadra & Nagar Haveli and Daman & Diu",
    "27": "Maharashtra",
    "29": "Karnataka",
    "30": "Goa",
    "31": "Lakshadweep",
    "32": "Kerala",
    "33": "Tamil Nadu",
    "34": "Puducherry",
    "35": "Andaman & Nicobar Islands",
    "36": "Telangana",
    "37": "Andhra Pradesh",
    "38": "Ladakh"
}

# Mock GST Registry Database
MOCK_GST_DB = {
    "29ABCDE1234F1Z5": {"legal_name": "Canara Verified User", "trade_name": "Canara Enterprise", "status": "ACTIVE", "state": "Karnataka", "pan": "ABCDE1234F"},
    "27TCSPL5566G1Z2": {"legal_name": "TATA CONSULTANCY SERVICES LIMITED", "trade_name": "TCS", "status": "ACTIVE", "state": "Maharashtra", "pan": "TCSPL5566G"},
    "29INFPL9988H1Z8": {"legal_name": "INFOSYS LIMITED", "trade_name": "Infosys", "status": "ACTIVE", "state": "Karnataka", "pan": "INFPL9988H"},
}

# Mock CIN Registry Database
MOCK_CIN_DB = {
    "U65110KA1906GOI003313": {"name": "CANARA BANK", "status": "ACTIVE", "incorporation_year": "1906", "state": "KA"},
    "L74140MH1995PLC090096": {"name": "TATA CONSULTANCY SERVICES LIMITED", "status": "ACTIVE", "incorporation_year": "1995", "state": "MH"},
    "L85110KA1981PLC013115": {"name": "INFOSYS LIMITED", "status": "ACTIVE", "incorporation_year": "1981", "state": "KA"},
}


def verify_gst_registry(gstin: str, company_name: str) -> dict:
    gstin = gstin.strip().upper() if gstin else ""
    company_name = company_name.strip() if company_name else ""
    
    # 1. Format check
    if not re.match(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$", gstin):
        return {"valid": False, "error": "Invalid GSTIN format", "reason_code": "GSTIN_FORMAT_INVALID"}
        
    # 2. State code verification
    state_code = gstin[:2]
    if state_code not in GST_STATE_CODES:
        return {"valid": False, "error": f"Invalid GST State Code '{state_code}'", "reason_code": "GST_STATE_CODE_INVALID"}
        
    state_name = GST_STATE_CODES[state_code]
    
    # 3. Lookup mock database
    gst_info = MOCK_GST_DB.get(gstin)
    if not gst_info:
        return {
            "valid": False,
            "error": f"GSTIN '{gstin}' not found in registry",
            "reason_code": "COMPANY_NOT_FOUND"
        }
        
    # 4. Legal / Trade name match (fuzzy matching)
    legal_name = gst_info["legal_name"]
    trade_name = gst_info["trade_name"]
    
    cleaned_input = clean_company_name(company_name)
    cleaned_legal = clean_company_name(legal_name)
    cleaned_trade = clean_company_name(trade_name)
    
    match_score = max(
        difflib.SequenceMatcher(None, company_name.lower(), legal_name.lower()).ratio(),
        difflib.SequenceMatcher(None, company_name.lower(), trade_name.lower()).ratio()
    )
    
    name_matched = False
    if (cleaned_input in cleaned_legal or cleaned_legal in cleaned_input or
        cleaned_input in cleaned_trade or cleaned_trade in cleaned_input or
        match_score >= 0.75):
        name_matched = True
        
    if not name_matched:
        return {
            "valid": False,
            "error": f"GST name mismatch: Registered names '{legal_name}' / '{trade_name}' do not match '{company_name}'",
            "reason_code": "COMPANY_NOT_FOUND",
            "match_score": round(match_score, 3)
        }
        
    return {
        "valid": True,
        "gstin": gstin,
        "legal_name": legal_name,
        "trade_name": trade_name,
        "status": gst_info["status"],
        "state": state_name,
        "pan": gst_info["pan"],
        "match_score": round(match_score, 3)
    }


def verify_cin_registry(cin: str, company_name: str) -> dict:
    cin = cin.strip().upper() if cin else ""
    company_name = company_name.strip() if company_name else ""
    
    # 1. CIN format validation
    if not re.match(r"^[U|L][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}$", cin):
        return {"valid": False, "error": "Invalid CIN format", "reason_code": "CIN_FORMAT_INVALID"}
        
    # Parse parts from CIN
    listing_status = "LISTED" if cin[0] == "L" else "UNLISTED"
    industry = cin[1:6]
    state_code = cin[6:8]
    incorporation_year = cin[8:12]
    class_code = cin[12:15]
    reg_num = cin[15:]
    
    # 2. Query in mock database
    found_info = None
    if cin in MOCK_CIN_DB:
        found_info = MOCK_CIN_DB[cin]
    else:
        for key, info in MOCK_COMPANIES.items():
            if info["cin"] == cin:
                found_info = {
                    "name": info["name"],
                    "status": info["status"],
                    "incorporation_year": incorporation_year,
                    "state": state_code
                }
                break
                
    if not found_info:
        return {
            "valid": False,
            "error": f"CIN '{cin}' not found in MCA registry",
            "reason_code": "COMPANY_NOT_FOUND"
        }
        
    # 3. Fuzzy company name check
    registered_name = found_info["name"]
    cleaned_input = clean_company_name(company_name)
    cleaned_reg = clean_company_name(registered_name)
    
    match_score = difflib.SequenceMatcher(None, company_name.lower(), registered_name.lower()).ratio()
    name_matched = False
    if cleaned_input in cleaned_reg or cleaned_reg in cleaned_input or match_score >= 0.75:
        name_matched = True
        
    if not name_matched:
        return {
            "valid": False,
            "error": f"MCA company name mismatch: Registered name '{registered_name}' does not match input '{company_name}'",
            "reason_code": "COMPANY_NOT_FOUND",
            "match_score": round(match_score, 3)
        }
        
    return {
        "valid": True,
        "cin": cin,
        "company_name": registered_name,
        "status": found_info["status"],
        "state": state_code,
        "incorporation_year": incorporation_year,
        "listing_status": listing_status,
        "match_score": round(match_score, 3)
    }
