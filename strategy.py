from flask import Flask, jsonify, redirect, render_template, request, Response, url_for
import requests
from fyers_apiv3 import fyersModel
app = Flask(__name__)
import pandas as pd
import time
import json


from collections import defaultdict
import csv

def export_dict_to_csv(data, filename="output.csv"):
    if not isinstance(data, dict):
        raise ValueError("Input data must be a dictionary.")

    # Extract unique field names dynamically
    all_keys = {"source"}  # Adding "source" to track original key
    rows = []

    for key, values in data.items():
        if not isinstance(values, list):
            continue  # Skip non-list values
        for item in values:
            if isinstance(item, dict):
                all_keys.update(item.keys())  # Collect all possible keys
                rows.append({"source": key, **item})  # Store rows

    if not rows:
        raise ValueError("No valid data found to write to CSV.")

    # Write to CSV
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(all_keys))
        writer.writeheader()
        writer.writerows(rows)

        
def process_oi_data(data, result_dict):

    # Ignore the first entry (equity data)
    index_data = data[0]
    options = data[1:]

    # Extract index name and LTP
    index_name = index_data["ex_symbol"]
    index_ltp = index_data["ltp"]

    # Separate call and put OI data
    call_oi_map = defaultdict(int)
    put_oi_map = defaultdict(int)

    for entry in options:
        strike = entry["strike_price"]
        oi = entry["oi"]

        if entry["option_type"] == "CE":
            call_oi_map[strike] = oi
        elif entry["option_type"] == "PE":
            put_oi_map[strike] = oi

    # Find the strike with the largest call OI
    if call_oi_map:
        max_call_strike, max_call_oi = max(call_oi_map.items(), key=lambda x: x[1])
        corresponding_put_oi = put_oi_map.get(max_call_strike, 0)
        call_put_oi_ratio = max_call_oi / (corresponding_put_oi or 1)
        ltp_strike_ratio = index_ltp / max_call_strike
    else:
        max_call_strike = max_call_oi = corresponding_put_oi = call_put_oi_ratio = ltp_strike_ratio = 0

    # Find the strike with the largest put OI
    if put_oi_map:
        max_put_strike, max_put_oi = max(put_oi_map.items(), key=lambda x: x[1])
        corresponding_call_oi = call_oi_map.get(max_put_strike, 0)
        put_call_oi_ratio = max_put_oi / (corresponding_call_oi or 1)
        strike_ltp_ratio = max_put_strike / index_ltp
    else:
        max_put_strike = max_put_oi = corresponding_call_oi = put_call_oi_ratio = strike_ltp_ratio = 0

    # Append results to dictionary
    result_dict["call"].append({
        "index_name": index_name,
        "ltp": index_ltp,
        "call_oi": max_call_oi,
        "put_oi": corresponding_put_oi,
        "call_put_oi_ratio": round(call_put_oi_ratio, 3),
        "strike": max_call_strike,
        "ltp_strike_ratio": round(ltp_strike_ratio, 3)
    })

    result_dict["put"].append({
        "index_name": index_name,
        "ltp": index_ltp,
        "put_oi": max_put_oi,
        "call_oi": corresponding_call_oi,
        "call_put_oi_ratio": round(put_call_oi_ratio, 3),
        "strike": max_put_strike,
        "ltp_strike_ratio": round(strike_ltp_ratio, 3)
    })

@app.route("/download_csv", methods=['GET'])
def download_csv():

    # URL of the CSV file
    url = "https://public.fyers.in/sym_details/NSE_FO.csv"

    # Read CSV directly from the URL with only the required column
    df = pd.read_csv(url, usecols=[13], header=None, names=["Stock"])

    # Drop duplicates
    df = df.drop_duplicates().reset_index(drop=True)

    # List of names to remove
    unwanted_list = ["BANKNIFTY", "FINNIFTY", "NIFTY", "NIFTYNXT50", "MIDCPNIFTY"]

    # Remove unwanted stock names
    df = df[~df["Stock"].isin(unwanted_list)]

    # Format stock names as "NSE:<stock_name>-EQ"
    df["Stock"] = "NSE:" + df["Stock"] + "-EQ"

    # Save the filtered data to a new CSV file
    output_file = "filtered_nse_fo.csv"
    df.to_csv(output_file, index=False, header=False)

    return Response(status=200)

def filter_call_put(data, call_filter_oi=None, call_filter_strike=None, put_filter_oi=None, put_filter_strike=None):
    
    # Apply filters efficiently using list comprehensions

    filtered_call = [
        entry for entry in data["call"]
        if (call_filter_oi is None or entry["call_put_oi_ratio"] >= call_filter_oi) and
           (call_filter_strike is None or entry["ltp_strike_ratio"] >= call_filter_strike)
    ]

    filtered_put = [
        entry for entry in data["put"]
        if (put_filter_oi is None or entry["call_put_oi_ratio"] >= put_filter_oi) and
           (put_filter_strike is None or entry["ltp_strike_ratio"] >= put_filter_strike)
    ]

    return {"call": filtered_call, "put": filtered_put}


@app.route("/")
def index():
    return render_template("strategy_page.html")

@app.route('/auth-form')
def auth_form():
    return render_template('oauth_form.html')  # The new page


@app.route('/login', methods=['POST'])
def create_token():
    import json
    data = json.loads(request.data)
    # app_id_hash = hashlib.sha256(f'{client_api_key}:{client_secret_key}'.encode()).hexdigest()

    FYERS_CLIENT_ID = data.get('client_id')

    # Generate the URL to redirect to
    target_url = f"https://api-t1.fyers.in/api/v3/generate-authcode?client_id={FYERS_CLIENT_ID}&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Ftoken&response_type=code&state=sample"

    # Return the target URL instead of redirecting
    return jsonify({'redirect_url': target_url})

@app.route('/token')
def callback_login():
    auth_code = request.args.get('auth_code')

    FYERS_SECRET_KEY = "H6I0D8T2OT"
    FYERS_CLIENT_ID = "RGB1I5PD6F-100"
    REDIRECT_URI = "http://127.0.0.1:5000/token"
    
    if auth_code:
        session_model = fyersModel.SessionModel(
            client_id=FYERS_CLIENT_ID,
            secret_key=FYERS_SECRET_KEY,
            redirect_uri=REDIRECT_URI,
            response_type="code",
            grant_type="authorization_code"
        )

        # Set the authorization code
        session_model.set_token(auth_code)

        # Generate the access token
        response = session_model.generate_token()

        if "access_token" in response:
            # Store the token (you can save it to the database instead)
            with open("config.json", "w") as f:
                json.dump({"access_token": response['access_token']}, f)

            return redirect(url_for('index'))  # Redirect to the home page
        else:
            return redirect(url_for('auth_form'))  # Redirect to login
    else:
        return redirect(url_for('index'))

@app.route("/data")
def get_data():
    call_filter_oi = request.args.get("col4_1", type=float, default=None)
    call_filter_strike = request.args.get("col6_1", type=float, default=None)
    put_filter_oi = request.args.get("col4_2", type=float, default=None)
    put_filter_strike = request.args.get("col6_2", type=float, default=None)
    export_to_csv = request.args.get("csv") == "true"
    
    print("data", put_filter_strike, put_filter_oi, export_to_csv)
    
    # Example loop that retrieves data and processes it
    result_dict = {"call": [], "put": []}

    t1 = time.time()
    
    # Read the CSV file with only the relevant column
    df = pd.read_csv("filtered_nse_fo.csv", usecols=[0], header=None, names=["Stock"])
    with open("config.json", "r") as f:
        data = json.load(f)  # Load JSON data from the file

    access_token = data.get("access_token")  # Extract the access token

    # Convert to a list for fast processing
    list_provided = df["Stock"].drop_duplicates().tolist()
    for index_name in list_provided[:30]:
        t2 = time.time()
        url = "https://api-t1.fyers.in/data/options-chain-v3"
        params = {"symbol": index_name, "strikecount": "15"}
        headers = {"Authorization": access_token}
        try:
            response = requests.get(url, headers=headers, params=params)
            response_json = response.json()

              # Check if the response contains an error
            if response.status_code == 429 or response_json.get('s') == 'error':
                print(f"Skipping {index_name}: {response_json.get('message', 'Unknown error')}")
                continue  # Skip this index_name and move to the next one
            else:
                data = response_json['data']['optionsChain']
                process_oi_data(data, result_dict)
        except requests.exceptions.RequestException as ex:
            print(f"API request failed for {index_name}. Ignoring and moving forward.")

        print("Time taken by one API ", time.time() - t2)
    final_data = filter_call_put(result_dict, call_filter_oi=call_filter_oi, call_filter_strike=call_filter_strike, put_filter_oi=put_filter_oi, put_filter_strike=put_filter_strike)
    
    if export_to_csv:
        export_dict_to_csv(final_data, "Oi-Csv-Data.csv")
    print("Total time taken in process ", time.time() - t1)
    return jsonify(final_data)

if __name__ == "__main__":
    app.run(debug=True)
